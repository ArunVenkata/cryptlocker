#!/bin/bash

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
INSTALL_NAME="cryptlocker"

# Check if the binary exists
if [ -f "${INSTALL_DIR}/${INSTALL_NAME}" ]; then
    # Remove the binary
    sudo rm "${INSTALL_DIR}/${INSTALL_NAME}"
    echo "Uninstallation complete: ${INSTALL_DIR}/${INSTALL_NAME}"
else
    echo "Error: ${INSTALL_DIR}/${INSTALL_NAME} not found."
    exit 1
fi