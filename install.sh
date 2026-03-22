#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────────

REPO="faramesh/faramesh-core"
BINARY_NAME="faramesh"
DEFAULT_INSTALL_DIR="/usr/local/bin"
FALLBACK_INSTALL_DIR="${HOME}/.local/bin"

# ─── Color & formatting ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()    { printf "${BLUE}${BOLD}▸${RESET} %s\n" "$*"; }
success() { printf "${GREEN}${BOLD}✔${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}${BOLD}⚠${RESET} %s\n" "$*"; }
error()   { printf "${RED}${BOLD}✘${RESET} %s\n" "$*" >&2; }
step()    { printf "\n${CYAN}${BOLD}── %s ──${RESET}\n\n" "$*"; }

die() {
    error "$@"
    exit 1
}

# ─── Defaults ───────────────────────────────────────────────────────────────────

VERSION="latest"
INSTALL_DIR=""
INTERACTIVE=true

# ─── Parse flags ────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"; shift 2 ;;
        --version=*)
            VERSION="${1#*=}"; shift ;;
        --install-dir)
            INSTALL_DIR="$2"; shift 2 ;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"; shift ;;
        --no-interactive)
            INTERACTIVE=false; shift ;;
        -h|--help)
            cat <<EOF
${BOLD}faramesh installer${RESET}

Usage: install.sh [OPTIONS]

Options:
  --version <ver>       Install a specific version (default: latest)
  --install-dir <path>  Custom install directory
  --no-interactive      Skip interactive prompts (CI-friendly)
  -h, --help            Show this help

Examples:
  curl -fsSL https://faramesh.dev/install.sh | bash
  curl -fsSL https://faramesh.dev/install.sh | bash -s -- --version 0.5.0
  curl -fsSL https://faramesh.dev/install.sh | bash -s -- --no-interactive
EOF
            exit 0 ;;
        *)
            die "Unknown flag: $1  (use --help for usage)" ;;
    esac
done

# ─── Banner ─────────────────────────────────────────────────────────────────────

print_banner() {
    printf "${MAGENTA}${BOLD}"
    cat <<'BANNER'

    ███████╗ █████╗ ██████╗  █████╗ ███╗   ███╗███████╗███████╗██╗  ██╗
    ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔════╝██║  ██║
    █████╗  ███████║██████╔╝███████║██╔████╔██║█████╗  ███████╗███████║
    ██╔══╝  ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
    ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗███████║██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝

BANNER
    printf "${RESET}"
    printf "    ${DIM}Pre-execution governance engine for AI agents${RESET}\n"
    printf "    ${DIM}https://faramesh.dev${RESET}\n\n"
}

print_banner

# ─── Platform detection ─────────────────────────────────────────────────────────

step "Detecting platform"

OS=""
ARCH=""

detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "${uname_s}" in
        Linux*)
            if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
                OS="windows"
                info "Detected Windows (WSL)"
            else
                OS="linux"
                info "Detected Linux"
            fi
            ;;
        Darwin*)
            OS="darwin"
            info "Detected macOS"
            ;;
        *)
            die "Unsupported operating system: ${uname_s}"
            ;;
    esac
}

detect_arch() {
    local uname_m
    uname_m="$(uname -m)"
    case "${uname_m}" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            die "Unsupported architecture: ${uname_m}"
            ;;
    esac
    info "Architecture: ${ARCH}"
}

detect_os
detect_arch

# ─── Resolve version ────────────────────────────────────────────────────────────

step "Resolving version"

if [ "${VERSION}" = "latest" ]; then
    info "Fetching latest release tag…"
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name":\s*"v?([^"]+)".*/\1/')" \
        || die "Failed to fetch latest release. Check your network or pass --version explicitly."
fi

success "Version: ${VERSION}"

# ─── Download ───────────────────────────────────────────────────────────────────

step "Downloading faramesh v${VERSION}"

TARBALL="faramesh_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUM_FILE="faramesh_${VERSION}_checksums.txt"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${TARBALL}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${CHECKSUM_FILE}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

info "Downloading ${DOWNLOAD_URL}"
curl -fSL --progress-bar -o "${TMPDIR}/${TARBALL}" "${DOWNLOAD_URL}" \
    || die "Download failed. Is v${VERSION} a valid release?"

info "Downloading checksum manifest"
curl -fsSL -o "${TMPDIR}/${CHECKSUM_FILE}" "${CHECKSUM_URL}" \
    || die "Checksum manifest download failed."

# ─── Verify SHA-256 ─────────────────────────────────────────────────────────────

step "Verifying SHA-256 checksum"

EXPECTED_SHA=""
EXPECTED_SHA="$(grep "${TARBALL}" "${TMPDIR}/${CHECKSUM_FILE}" | awk '{print $1}')"

if [ -z "${EXPECTED_SHA}" ]; then
    die "Could not find checksum for ${TARBALL} in manifest."
fi

if command -v sha256sum &>/dev/null; then
    ACTUAL_SHA="$(sha256sum "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
elif command -v shasum &>/dev/null; then
    ACTUAL_SHA="$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
else
    die "Neither sha256sum nor shasum found. Cannot verify checksum."
fi

if [ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]; then
    error "Checksum mismatch!"
    error "  expected: ${EXPECTED_SHA}"
    error "  actual:   ${ACTUAL_SHA}"
    die "The downloaded file may be corrupted or tampered with."
fi

success "Checksum verified: ${ACTUAL_SHA:0:16}…"

# ─── Extract ────────────────────────────────────────────────────────────────────

info "Extracting archive"
tar -xzf "${TMPDIR}/${TARBALL}" -C "${TMPDIR}"

if [ ! -f "${TMPDIR}/${BINARY_NAME}" ]; then
    die "Expected binary '${BINARY_NAME}' not found in archive."
fi

chmod +x "${TMPDIR}/${BINARY_NAME}"

# ─── Install ────────────────────────────────────────────────────────────────────

step "Installing"

resolve_install_dir() {
    if [ -n "${INSTALL_DIR}" ]; then
        return
    fi

    if [ -w "${DEFAULT_INSTALL_DIR}" ]; then
        INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
    elif command -v sudo &>/dev/null; then
        INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
    else
        INSTALL_DIR="${FALLBACK_INSTALL_DIR}"
        mkdir -p "${INSTALL_DIR}"
    fi
}

resolve_install_dir

info "Installing to ${INSTALL_DIR}/${BINARY_NAME}"

if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    warn "Elevated permissions required for ${INSTALL_DIR}"
    sudo mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# Ensure install dir is on PATH
case ":${PATH}:" in
    *:"${INSTALL_DIR}":*) ;;
    *)
        warn "${INSTALL_DIR} is not in your PATH."
        warn "Add this to your shell profile:"
        printf "    ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n" "${INSTALL_DIR}"
        ;;
esac

# ─── Verify installation ────────────────────────────────────────────────────────

step "Verifying installation"

INSTALLED_VERSION="$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>&1)" \
    || die "Installed binary failed to execute."

success "faramesh ${INSTALLED_VERSION} installed successfully"

# ─── Interactive onboarding ─────────────────────────────────────────────────────

if [ "${INTERACTIVE}" = true ] && [ -t 0 ]; then
    step "Getting started"

    printf "${BOLD}Run the 30-second demo?${RESET} [Y/n] "
    read -r DEMO_ANSWER </dev/tty
    DEMO_ANSWER="${DEMO_ANSWER:-Y}"
    if [[ "${DEMO_ANSWER}" =~ ^[Yy]$ ]]; then
        printf "\n"
        "${INSTALL_DIR}/${BINARY_NAME}" demo || warn "Demo exited with non-zero status."
        printf "\n"
    fi

    printf "${BOLD}Auto-detect your environment?${RESET} [Y/n] "
    read -r DETECT_ANSWER </dev/tty
    DETECT_ANSWER="${DETECT_ANSWER:-Y}"
    if [[ "${DETECT_ANSWER}" =~ ^[Yy]$ ]]; then
        printf "\n"
        "${INSTALL_DIR}/${BINARY_NAME}" init --auto-detect || warn "Auto-detect exited with non-zero status."
        printf "\n"
    fi
fi

# ─── Next steps ──────────────────────────────────────────────────────────────────

step "Next steps"

printf "  ${BOLD}1.${RESET} Create a policy:          ${CYAN}faramesh init${RESET}\n"
printf "  ${BOLD}2.${RESET} Run a governed command:    ${CYAN}faramesh run -- python agent.py${RESET}\n"
printf "  ${BOLD}3.${RESET} View the dashboard:        ${CYAN}faramesh serve${RESET}\n"
printf "\n"
printf "  ${DIM}Documentation:${RESET}  ${BLUE}https://docs.faramesh.dev${RESET}\n"
printf "  ${DIM}GitHub:${RESET}         ${BLUE}https://github.com/${REPO}${RESET}\n"
printf "  ${DIM}Community:${RESET}      ${BLUE}https://discord.gg/faramesh${RESET}\n"
printf "\n"
success "You're all set. Happy governing!"
printf "\n"
