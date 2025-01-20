#!/bin/bash

set -e

# Configuration
REPO_OWNER="ArunVenkata"
REPO_NAME="cryptlocker"
BINARY_NAME="cryptlocker"
INSTALL_DIR="/usr/local/bin"
INSTALL_NAME="cryptlocker"
PUBLIC_KEY_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/raw/master/pubkey.gpg"

# Fetch the latest release version
VERSION=$(curl -s https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
# gets the latest version 

# Construct download URLs
DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${BINARY_NAME}"
SIGNATURE_URL="${DOWNLOAD_URL}.sig"

# Create temporary directory
TMP_DIR=$(mktemp -d)
TMP_FILE="${TMP_DIR}/${BINARY_NAME}"
TMP_SIGNATURE="${TMP_DIR}/${BINARY_NAME}.sig"
TMP_PUBLIC_KEY="${TMP_DIR}/pubkey.gpg"

# Download files
echo "Downloading binary, signature, and public key..."
curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
curl -sL "$SIGNATURE_URL" -o "$TMP_SIGNATURE"
curl -sL "$PUBLIC_KEY_URL" -o "$TMP_PUBLIC_KEY"

# Check if gpg is installed
if command -v gpg > /dev/null 2>&1; then
    # Import the public GPG key
    gpg --import "$TMP_PUBLIC_KEY" > /dev/null 2>&1

    # Verify the GPG signature
    if gpg --verify "$TMP_SIGNATURE" "$TMP_FILE" > /dev/null 2>&1; then
        echo "GPG Signature Successfully Verified."
    else
        echo "GPG signature verification failed!"
        exit 1
    fi
else
    echo "GPG not found, skipping signature verification."
fi

# Move the binary to the installation directory and rename it to "cryptlocker"
sudo mv "$TMP_FILE" "${INSTALL_DIR}/${INSTALL_NAME}"
sudo chmod +x "${INSTALL_DIR}/${INSTALL_NAME}"

# Clean up
rm -rf "$TMP_DIR"

echo "Installation complete: ${INSTALL_DIR}/${INSTALL_NAME}"