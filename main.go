package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

//go:embed static/index.html
var staticFiles embed.FS

const (
	MaxUploadSize = 3 << 20 // 3 MB
	JobRetention  = 10 * time.Minute
)

// JobResult holds the P12 job outcome returned by /result/<id>
type JobResult struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"` // "processing", "good", "revoked", "unknown", "error"
	RevokedAt    string    `json:"revoked_at,omitempty"`
	SerialNumber string    `json:"serial,omitempty"`
	Message      string    `json:"message,omitempty"`
	CertInfo     string    `json:"cert_info,omitempty"`
	CreatedAt    time.Time `json:"-"`
	MPMatch      *bool     `json:"mp_match,omitempty"`
	MPMessage    string    `json:"mp_message,omitempty"`
}

type IPACertCheckRequest struct {
	Certs []string `json:"certs"`
}

type CertOCSPResult struct {
	Status         string `json:"status"`
	Subject        string `json:"subject"`
	Serial         string `json:"serial"`
	Message        string `json:"message"`
	RevokedAt      string `json:"revoked_at,omitempty"`
	CertInfo       string `json:"cert_info"`
	IssuerNotFound bool   `json:"issuer_not_found,omitempty"`
}

var (
	store   = make(map[string]JobResult)
	storeMu sync.RWMutex

	// Clients configured to prevent SSRF
	safeOCSPClient      = createSSRFSafeClient(10 * time.Second)
	safeCertFetcherClient = createSSRFSafeClient(5 * time.Second)
)

func saveResult(id string, r JobResult) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	store[id] = r
}

func getResult(id string) (JobResult, bool) {
	storeMu.RLock()
	defer storeMu.RUnlock()
	r, ok := store[id]
	return r, ok
}

func cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		storeMu.Lock()
		now := time.Now()
		for id, job := range store {
			if now.Sub(job.CreatedAt) > JobRetention {
				delete(store, id)
			}
		}
		storeMu.Unlock()
	}
}

func main() {
	host := flag.String("host", "", "Host to bind the server to (e.g., '127.0.0.1')")
	port := flag.String("port", "6969", "Port to bind the server to")
	flag.Parse()

	go cleanupRoutine()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/upload-p12", p12UploadHandler)
	mux.HandleFunc("/check-ipa-certs", ipaCheckHandler)
	mux.HandleFunc("/result/", resultHandler)

	addr := *host + ":" + *port
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, err := staticFiles.Open("static/index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	readSeeker, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "internal file error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, "index.html", time.Now(), readSeeker)
}

// p12UploadHandler accepts a p12 file (required) and an optional mobileprovision file.
// It starts an async job to check OCSP for the certificate and optionally check
// whether the embedded.mobileprovision contains a matching certificate.
func p12UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)
	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, fh, err := r.FormFile("p12file")
	if err != nil {
		http.Error(w, "missing p12file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	password := r.FormValue("password")

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	var mpBytes []byte
	mpFile, _, mpErr := r.FormFile("mobileprovision")
	if mpErr == nil && mpFile != nil {
		defer mpFile.Close()
		mpBytes, _ = io.ReadAll(mpFile)
	}

	log.Printf("P12 Job received: %s (%d bytes) mobileprovision=%v", fh.Filename, len(data), mpBytes != nil)

	id := uuid.New().String()
	saveResult(id, JobResult{ID: id, Status: "processing", Message: "queued", CreatedAt: time.Now()})

	go func(jobID string, p12data []byte, pass string, mobileprov []byte) {
		res := processP12AndOCSP(p12data, pass, mobileprov)
		res.ID = jobID
		res.CreatedAt = time.Now()
		saveResult(jobID, res)
	}(id, data, password, mpBytes)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

// ipaCheckHandler checks multiple public certs (base64) from an IPA against OCSP.
func ipaCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var reqData IPACertCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if len(reqData.Certs) == 0 {
		http.Error(w, "No certificates provided", http.StatusBadRequest)
		return
	}

	log.Printf("IPA Cert Check job received: %d certs", len(reqData.Certs))

	var results []CertOCSPResult
	var wg sync.WaitGroup
	resultsChan := make(chan CertOCSPResult, len(reqData.Certs))

	for _, certB64 := range reqData.Certs {
		wg.Add(1)
		go func(b64 string) {
			defer wg.Done()
			certData, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				resultsChan <- CertOCSPResult{Status: "error", Message: "Invalid Base64"}
				return
			}
			resultsChan <- processPublicCertAndOCSP(certData)
		}(certB64)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		results = append(results, res)
	}

	log.Printf("IPA Cert Check job finished: %d results", len(results))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func resultHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/result/")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	res, ok := getResult(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// formatCertInfo turns an x509.Certificate into a compact, readable string.
func formatCertInfo(cert *x509.Certificate) string {
	var info strings.Builder
	info.WriteString(fmt.Sprintf("Subject: %s\n", cert.Subject.String()))
	info.WriteString(fmt.Sprintf("Issuer: %s\n", cert.Issuer.String()))
	info.WriteString(fmt.Sprintf("Serial: %s\n", cert.SerialNumber.String()))
	info.WriteString(fmt.Sprintf("Valid From: %s\n", cert.NotBefore.Format(time.RFC1123)))
	info.WriteString(fmt.Sprintf("Valid Until: %s\n", cert.NotAfter.Format(time.RFC1123)))
	return info.String()
}

// processPublicCertAndOCSP checks OCSP for a single public certificate (from an IPA).
func processPublicCertAndOCSP(certData []byte) CertOCSPResult {
	leafCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return CertOCSPResult{Status: "error", Message: "Failed to parse certificate: " + err.Error()}
	}

	serial := leafCert.SerialNumber.String()
	subject := leafCert.Subject.String()
	certInfo := formatCertInfo(leafCert)

	if len(leafCert.OCSPServer) == 0 {
		return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "Certificate does not have an OCSP server defined"}
	}
	ocspURL := leafCert.OCSPServer[0]

	// Attempt to find issuer
	var issuer *x509.Certificate
	if len(leafCert.IssuingCertificateURL) > 0 {
		for _, url := range leafCert.IssuingCertificateURL {
			ic, err := fetchCertFromURL(url)
			if err == nil && ic != nil {
				if err := leafCert.CheckSignatureFrom(ic); err == nil {
					issuer = ic
					break
				}
			}
		}
	}

	if issuer == nil {
		return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "Issuer certificate could not be found.", IssuerNotFound: true}
	}

	ocspReqBytes, err := ocsp.CreateRequest(leafCert, issuer, nil)
	if err != nil {
		return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "Failed to create OCSP request: " + err.Error()}
	}

	ocspResp, err := sendOCSPRequest(ocspURL, ocspReqBytes, leafCert)
	if err != nil {
		return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: err.Error()}
	}

	parsed, err := ocsp.ParseResponseForCert(ocspResp, leafCert, issuer)
	if err != nil {
		unverifiedResp, errParse := ocsp.ParseResponse(ocspResp, nil)
		if errParse == nil && unverifiedResp != nil && int(unverifiedResp.Status) == int(ocsp.Unauthorized) {
			return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "OCSP responder returned: Unauthorized."}
		}
		return CertOCSPResult{Status: "error", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "Invalid OCSP response signature: " + err.Error()}
	}

	switch parsed.Status {
	case ocsp.Good:
		return CertOCSPResult{Status: "good", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "Certificate is VALID"}
	case ocsp.Revoked:
		return CertOCSPResult{Status: "revoked", Serial: serial, Subject: subject, CertInfo: certInfo, RevokedAt: parsed.RevokedAt.UTC().Format(time.RFC3339), Message: fmt.Sprintf("Certificate was REVOKED at %s reason: %d", parsed.RevokedAt, parsed.RevocationReason)}
	default:
		return CertOCSPResult{Status: "unknown", Serial: serial, Subject: subject, CertInfo: certInfo, Message: "OCSP status UNKNOWN"}
	}
}

// processP12AndOCSP checks a P12 file, queries OCSP for its leaf cert,
// and if a mobileprovision was provided, tries to confirm a match.
func processP12AndOCSP(p12data []byte, password string, mobileprov []byte) JobResult {
	blocks, err := pkcs12.ToPEM(p12data, password)
	if err != nil {
		return JobResult{Status: "error", Message: "Incorrect password or invalid P12: " + err.Error()}
	}

	var leafCert *x509.Certificate
	var chainCerts []*x509.Certificate

	for _, b := range blocks {
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				continue
			}
			// pick non-CA as leaf if possible
			if !cert.IsCA && leafCert == nil {
				leafCert = cert
			} else {
				chainCerts = append(chainCerts, cert)
			}
		}
	}

	// fallback heuristics
	if leafCert == nil {
		for _, b := range blocks {
			if b.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
					leafCert = cert
					break
				}
			}
		}
	}

	if leafCert == nil {
		return JobResult{Status: "error", Message: "No certificates found in P12"}
	}

	serial := leafCert.SerialNumber.String()
	certInfo := formatCertInfo(leafCert)

	if len(leafCert.OCSPServer) == 0 {
		return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: "Certificate does not have an OCSP server defined"}
	}
	ocspURL := leafCert.OCSPServer[0]

	// Find issuer in chain
	var issuer *x509.Certificate
	for _, c := range chainCerts {
		if c.Subject.String() == leafCert.Issuer.String() {
			if err := leafCert.CheckSignatureFrom(c); err == nil {
				issuer = c
				break
			}
		}
	}

	// Try fetching issuer if not in chain
	if issuer == nil && len(leafCert.IssuingCertificateURL) > 0 {
		for _, url := range leafCert.IssuingCertificateURL {
			ic, err := fetchCertFromURL(url)
			if err == nil && ic != nil {
				if err := leafCert.CheckSignatureFrom(ic); err == nil {
					issuer = ic
					log.Printf("Fetched issuer for %s from %s", leafCert.Subject.String(), url)
					break
				}
			}
		}
	}

	if issuer == nil {
		return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: "Issuer certificate not found. Please include full chain in P12."}
	}

	ocspReqBytes, err := ocsp.CreateRequest(leafCert, issuer, nil)
	if err != nil {
		return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: "Failed to create OCSP request: " + err.Error()}
	}

	ocspResp, err := sendOCSPRequest(ocspURL, ocspReqBytes, leafCert)
	if err != nil {
		return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: err.Error()}
	}

	parsed, err := ocsp.ParseResponseForCert(ocspResp, leafCert, issuer)
	if err != nil {
		unverifiedResp, errParse := ocsp.ParseResponse(ocspResp, nil)
		if errParse == nil && unverifiedResp != nil && int(unverifiedResp.Status) == int(ocsp.Unauthorized) {
			return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: "OCSP responder returned: Unauthorized."}
		}
		return JobResult{Status: "error", SerialNumber: serial, CertInfo: certInfo, Message: "Invalid OCSP response signature: " + err.Error()}
	}

	// If a mobileprovision was supplied, try to parse and compare certs
	var mpMatch *bool
	var mpMsg string
	if len(mobileprov) > 0 {
		provCerts, perr := parseMobileProvision(mobileprov)
		if perr != nil {
			mpFalse := false
			mpMatch = &mpFalse
			mpMsg = "Failed to parse mobileprovision: " + perr.Error()
		} else {
			found := false
			for _, pc := range provCerts {
				if pc == nil {
					continue
				}
				// Compare certificate public key bytes (SubjectPublicKeyInfo) if available
				if len(pc.RawSubjectPublicKeyInfo) > 0 && len(leafCert.RawSubjectPublicKeyInfo) > 0 {
					if bytes.Equal(pc.RawSubjectPublicKeyInfo, leafCert.RawSubjectPublicKeyInfo) {
						found = true
						break
					}
				}
				// fallback to subject comparison
				if pc.Subject.String() == leafCert.Subject.String() {
					found = true
					break
				}
			}
			mpTrue := found
			mpMatch = &mpTrue
			if found {
				mpMsg = "mobileprovision appears to contain a matching certificate"
			} else {
				mpMsg = "no matching certificate found in mobileprovision"
			}
		}
	}

	switch parsed.Status {
	case ocsp.Good:
		return JobResult{Status: "good", SerialNumber: serial, CertInfo: certInfo, Message: "Certificate is VALID", MPMatch: mpMatch, MPMessage: mpMsg}
	case ocsp.Revoked:
		return JobResult{Status: "revoked", SerialNumber: serial, CertInfo: certInfo, RevokedAt: parsed.RevokedAt.UTC().Format(time.RFC3339), Message: fmt.Sprintf("Certificate was REVOKED at %s reason: %d", parsed.RevokedAt, parsed.RevocationReason), MPMatch: mpMatch, MPMessage: mpMsg}
	default:
		return JobResult{Status: "unknown", SerialNumber: serial, CertInfo: certInfo, Message: "OCSP status UNKNOWN", MPMatch: mpMatch, MPMessage: mpMsg}
	}
}

func sendOCSPRequest(ocspURL string, reqBytes []byte, leaf *x509.Certificate) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ocspURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")
	httpReq.Header.Set("User-Agent", "Go-OCSP-Checker/1.0")

	httpResp, err := safeOCSPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OCSP network error: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder error: %d", httpResp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}
	return respBytes, nil
}

func fetchCertFromURL(url string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Go-OCSP-Checker/1.0")

	resp, err := safeCertFetcherClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}

	// Try DER first
	if cert, err := x509.ParseCertificate(b); err == nil {
		return cert, nil
	}

	// Try PEM
	block, _ := pem.Decode(b)
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert, nil
		}
	}
	return nil, errors.New("unable to parse certificate")
}

var privateIPBlocks []*net.IPNet

func init() {
	// Initialize private IP blocks for SSRF protection
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("failed to parse private IP CIDR %q: %v", cidr, err)
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// createSSRFSafeClient returns an http.Client that blocks requests to private IPs.
func createSSRFSafeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address: %w", err)
				}

				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("failed to resolve host: %w", err)
				}

				if len(ips) == 0 {
					return nil, errors.New("no IPs found for host")
				}

				var firstPublicIP net.IP
				for _, ipAddr := range ips {
					if isPrivateIP(ipAddr.IP) {
						log.Printf("Blocked SSRF attempt to private IP %s (%s)", ipAddr.IP.String(), host)
						return nil, fmt.Errorf("blocked request to private/reserved IP: %s", ipAddr.IP.String())
					}
					if firstPublicIP == nil {
						// Grab the first IP that passed the check
						firstPublicIP = ipAddr.IP
					}
				}

				if firstPublicIP == nil {
					// This case should be impossible if len(ips) > 0 and none are private,
					// but it's a good safeguard.
					return nil, errors.New("no public IP found for host")
				}

				// We must dial the IP address, not the hostname, to avoid a TOCTOU race
				// where DNS could change between our check and the dialer's lookup.
				safeAddr := net.JoinHostPort(firstPublicIP.String(), port)

				var d net.Dialer
				d.Timeout = 10 * time.Second // Keep a reasonable dial timeout
				return d.DialContext(ctx, network, safeAddr)
			},
		},
	}
}

// parseMobileProvision attempts to extract DeveloperCertificates from a .mobileprovision
// file and returns parsed x509 certificates. It tolerates common variations by searching
// for the XML portion and extracting <data> blocks inside the DeveloperCertificates array.
func parseMobileProvision(raw []byte) ([]*x509.Certificate, error) {
	str := string(raw)
	idx := strings.Index(str, "<?xml")
	if idx == -1 {
		return nil, errors.New("no XML plist found")
	}
	xml := str[idx:]
	key := "<key>DeveloperCertificates</key>"
	kidx := strings.Index(xml, key)
	if kidx == -1 {
		return nil, errors.New("DeveloperCertificates not present")
	}
	ai := strings.Index(xml[kidx:], "<array>")
	if ai == -1 {
		return nil, errors.New("DeveloperCertificates array not found")
	}
	aj := strings.Index(xml[kidx+ai:], "</array>")
	if aj == -1 {
		return nil, errors.New("DeveloperCertificates array not closed")
	}
	arrayBlock := xml[kidx+ai : kidx+ai+aj]

	var certs []*x509.Certificate
	search := arrayBlock
	for {
		si := strings.Index(search, "<data>")
		if si == -1 {
			break
		}
		sj := strings.Index(search[si:], "</data>")
		if sj == -1 {
			break
		}
		dataBlock := search[si+len("<data>") : si+sj]
		// remove whitespace/newlines
		dataBlock = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
				return -1
			}
			return r
		}, dataBlock)
		decoded, err := base64.StdEncoding.DecodeString(dataBlock)
		if err == nil {
			if cert, err := x509.ParseCertificate(decoded); err == nil {
				certs = append(certs, cert)
			}
		}
		search = search[si+sj+len("</data>"):]
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates extracted from mobileprovision")
	}
	return certs, nil
}