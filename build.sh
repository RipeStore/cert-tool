#!/bin/bash
set -e

# Define the application name
APP_NAME="ocsp-checker"

# Create a build directory if it doesn't exist
mkdir -p build

# The matrix of OS/Arch combinations
# Format: "GOOS/GOARCH"
targets=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
    "windows/amd64"
    "windows/arm64"
    "windows/386"
    "darwin/amd64"
    "darwin/arm64"
)

echo "Starting build process for $APP_NAME..."

for target in "${targets[@]}"; do
    # Split the target string into OS and ARCH
    # (Using bash string manipulation because I refuse to use cut here)
    GOOS=${target%%/*}
    GOARCH=${target##*/}

    # Determine the output filename
    output_name="${APP_NAME}-${GOOS}-${GOARCH}"

    # Add .exe extension for Windows builds
    if [ "$GOOS" == "windows" ]; then
        output_name+=".exe"
    fi

    echo "Compiling for $GOOS ($GOARCH)..."
    
    # Run the build
    # -s: disable symbol table
    # -w: disable DWARF generation
    env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "build/$output_name"

    if [ $? -eq 0 ]; then
        echo "  > Success: build/$output_name"
    else
        echo "  > Failed to build for $GOOS/$GOARCH"
        exit 1
    fi
done

echo "--------------------------------------"
echo "All builds complete. Check the 'build' directory."
