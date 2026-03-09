#!/usr/bin/env sh
# Faramesh install script
# Usage: curl -fsSL https://raw.githubusercontent.com/faramesh/faramesh-core/main/install.sh | sh
set -e

REPO="faramesh/faramesh-core"
BINARY="faramesh"

# ── Detect OS and architecture ──────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)   OS_SLUG="linux" ;;
  Darwin)  OS_SLUG="darwin" ;;
  *)
    echo "Unsupported OS: $OS"
    echo "Download manually: https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64 | amd64)  ARCH_SLUG="amd64" ;;
  arm64 | aarch64) ARCH_SLUG="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Download manually: https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

ASSET_NAME="${BINARY}-${OS_SLUG}-${ARCH_SLUG}"

# ── Resolve latest version ───────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  echo "Error: curl or wget is required"
  exit 1
fi

VERSION="$(${FETCH} "https://api.github.com/repos/${REPO}/releases/latest" | \
  grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

if [ -z "$VERSION" ]; then
  echo "Error: could not determine latest version"
  exit 1
fi

echo "Installing faramesh ${VERSION} (${OS_SLUG}/${ARCH_SLUG})..."

# ── Download ─────────────────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

${FETCH} "$DOWNLOAD_URL" -o "${TMP_DIR}/${BINARY}" 2>/dev/null || \
  ${FETCH} "$DOWNLOAD_URL" > "${TMP_DIR}/${BINARY}"

# ── Verify SHA256 ─────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then
  EXPECTED="$(${FETCH} "$CHECKSUM_URL" | awk '{print $1}')"
  ACTUAL="$(sha256sum "${TMP_DIR}/${BINARY}" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "SHA256 mismatch!"
    echo "  expected: $EXPECTED"
    echo "  actual:   $ACTUAL"
    exit 1
  fi
elif command -v shasum >/dev/null 2>&1; then
  EXPECTED="$(${FETCH} "$CHECKSUM_URL" | awk '{print $1}')"
  ACTUAL="$(shasum -a 256 "${TMP_DIR}/${BINARY}" | awk '{print $1}')"
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "SHA256 mismatch!"
    echo "  expected: $EXPECTED"
    echo "  actual:   $ACTUAL"
    exit 1
  fi
fi

chmod +x "${TMP_DIR}/${BINARY}"

# ── Install ───────────────────────────────────────────────────────────────────
INSTALL_DIR=""

# Try standard locations in order of preference
for dir in /usr/local/bin /usr/bin "$HOME/.local/bin"; do
  if [ -d "$dir" ] && [ -w "$dir" ]; then
    INSTALL_DIR="$dir"
    break
  fi
done

# Fall back to ~/.local/bin (create if needed)
if [ -z "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

# If target dir exists but isn't writable, try sudo
if [ -d "$INSTALL_DIR" ] && [ ! -w "$INSTALL_DIR" ]; then
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "✓ Installed faramesh ${VERSION} → ${INSTALL_DIR}/${BINARY}"
echo ""

# Warn if install dir is not on PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "  Add to PATH:  export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
    ;;
esac

echo "  Next steps:"
echo "    faramesh demo            # See governance in action"
echo "    faramesh init            # Auto-detect env, generate policy"
echo "    faramesh serve --policy policy.yaml"
echo ""
echo "  Docs: https://faramesh.dev/docs"
