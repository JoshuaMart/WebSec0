#!/bin/sh
# WebSec0 installer
# Usage: curl -sSL https://raw.githubusercontent.com/JoshuaMart/websec0/main/scripts/install.sh | sh
#
# Options (via environment variables):
#   WEBSEC0_VERSION   — specific version to install (default: latest)
#   WEBSEC0_BINARY    — which binary to install: websec0 or websec0-cli (default: websec0)
#   INSTALL_DIR       — installation directory (default: /usr/local/bin)
#   VERIFY_COSIGN     — set to "1" to verify cosign bundle (requires cosign ≥ 3.0)
set -e

REPO="JoshuaMart/websec0"
BINARY="${WEBSEC0_BINARY:-websec0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERIFY_COSIGN="${VERIFY_COSIGN:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

info()  { printf "${GREEN}[websec0]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[websec0]${RESET} %s\n" "$*" >&2; }
error() { printf "${RED}[error]${RESET} %s\n" "$*" >&2; exit 1; }

# Detect OS
case "$(uname -s)" in
  Linux)  OS="Linux" ;;
  Darwin) OS="Darwin" ;;
  *)      error "Unsupported OS: $(uname -s). Install manually from https://github.com/${REPO}/releases" ;;
esac

# Detect architecture
case "$(uname -m)" in
  x86_64 | amd64)  ARCH="x86_64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)               error "Unsupported architecture: $(uname -m)" ;;
esac

# Resolve version
if [ -z "${WEBSEC0_VERSION}" ]; then
  info "Fetching latest release version..."
  VERSION="$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  [ -z "${VERSION}" ] && error "Could not determine latest version. Set WEBSEC0_VERSION manually."
else
  VERSION="${WEBSEC0_VERSION}"
fi

info "Installing ${BINARY} ${VERSION} (${OS}/${ARCH})..."

# Build archive name based on binary
if [ "${BINARY}" = "websec0-cli" ]; then
  ARCHIVE_NAME="websec0-cli_${VERSION#v}_${OS}_${ARCH}"
else
  ARCHIVE_NAME="websec0_${VERSION#v}_${OS}_${ARCH}"
fi

EXT="tar.gz"
[ "${OS}" = "Windows" ] && EXT="zip"
ARCHIVE="${ARCHIVE_NAME}.${EXT}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Download to a temp directory
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

info "Downloading ${ARCHIVE}..."
curl -sSfL "${BASE_URL}/${ARCHIVE}" -o "${TMP}/${ARCHIVE}"
curl -sSfL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"

# Verify SHA256 checksum
info "Verifying checksum..."
cd "${TMP}"
if command -v sha256sum >/dev/null 2>&1; then
  grep "${ARCHIVE}" checksums.txt | sha256sum --check --status \
    || error "SHA256 checksum mismatch for ${ARCHIVE}"
elif command -v shasum >/dev/null 2>&1; then
  grep "${ARCHIVE}" checksums.txt | shasum -a 256 --check --status \
    || error "SHA256 checksum mismatch for ${ARCHIVE}"
else
  warn "Neither sha256sum nor shasum found — skipping checksum verification"
fi
info "Checksum OK"

# Optionally verify cosign bundle signature
if [ "${VERIFY_COSIGN}" = "1" ]; then
  if command -v cosign >/dev/null 2>&1; then
    info "Verifying cosign bundle signature..."
    curl -sSfL "${BASE_URL}/checksums.txt.bundle" -o "${TMP}/checksums.txt.bundle"
    cosign verify-blob \
      --bundle "${TMP}/checksums.txt.bundle" \
      "${TMP}/checksums.txt" \
      || error "Cosign signature verification failed"
    info "Cosign signature OK"
  else
    warn "cosign not found — skipping bundle verification (install from https://github.com/sigstore/cosign)"
  fi
fi

# Extract
info "Extracting..."
cd "${TMP}"
if [ "${EXT}" = "zip" ]; then
  command -v unzip >/dev/null 2>&1 || error "unzip not found"
  unzip -q "${ARCHIVE}"
else
  tar xzf "${ARCHIVE}"
fi

# Install
BINARY_PATH="${TMP}/${BINARY}"
[ -f "${BINARY_PATH}" ] || error "Binary '${BINARY}' not found in archive"

if [ -w "${INSTALL_DIR}" ]; then
  mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY}"
else
  info "Requesting sudo to install to ${INSTALL_DIR}..."
  sudo mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY}"
fi
chmod +x "${INSTALL_DIR}/${BINARY}"

info "${BINARY} ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
info "Run '${BINARY} --help' to get started."
