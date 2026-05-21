#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────────

REPO="faramesh/faramesh-core"
BINARY_NAME="faramesh"
INSTALL_BINARY_NAME="faramesh"
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
UPDATE_MODE=false

append_search_dir() {
    local dir="$1"
    [ -n "$dir" ] || return 0
    SEARCH_DIRS+=("$dir")
}

discover_faramesh_paths() {
    {
        if command -v type >/dev/null 2>&1; then
            type -aP faramesh 2>/dev/null || true
        fi

        local -a SEARCH_DIRS=()
        local -a path_parts=()
        local dir

        IFS=':' read -r -a path_parts <<< "${PATH:-}"
        SEARCH_DIRS+=("${path_parts[@]}")
        SEARCH_DIRS+=(
            "${HOME}/.local/bin"
            "/usr/local/bin"
            "/usr/local/sbin"
            "/opt/homebrew/bin"
            "/opt/homebrew/sbin"
            "/usr/local/opt"
            "/opt/homebrew/opt"
            "${HOME}/go/bin"
            "${HOME}/.cargo/bin"
            "/opt/local/bin"
            "/opt/local/sbin"
            "${HOME}/bin"
        )

        if command -v brew >/dev/null 2>&1; then
            local brew_prefix
            brew_prefix="$(brew --prefix 2>/dev/null || true)"
            append_search_dir "${brew_prefix}/bin"
            append_search_dir "${brew_prefix}/sbin"
        fi

        if command -v go >/dev/null 2>&1; then
            local gopath
            gopath="$(go env GOPATH 2>/dev/null || true)"
            append_search_dir "${gopath}/bin"
        fi

        if command -v npm >/dev/null 2>&1; then
            local npm_prefix
            npm_prefix="$(npm config get prefix 2>/dev/null || true)"
            append_search_dir "${npm_prefix}/bin"
        fi

        for dir in "${SEARCH_DIRS[@]}"; do
            [ -d "${dir}" ] || continue
            find "${dir}" -maxdepth 2 \( -type f -o -type l \) \( -name faramesh -o -name faramesh.exe \) 2>/dev/null || true
        done
    } | awk '!seen[$0]++' | sed '/^$/d'
}

discover_install_dir() {
    local existing_path
    while IFS= read -r existing_path; do
        if [ -n "${existing_path}" ]; then
            dirname "${existing_path}"
            return 0
        fi
    done < <(discover_faramesh_paths)

    return 1
}
# ─── Parse flags ────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"; shift 2 ;;
        --version=*)
            VERSION="${1#*=}"; shift ;;
        --update)
            UPDATE_MODE=true; shift ;;
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
    --update              Update the current install in place (keeps data)
  --install-dir <path>  Custom install directory
  --no-interactive      Skip interactive prompts (CI-friendly)
  -h, --help            Show this help

Examples:
    curl -fsSL https://install.faramesh.dev/install.sh | bash
    curl -fsSL https://install.faramesh.dev/install.sh | bash -s -- --version 0.5.0
    curl -fsSL https://install.faramesh.dev/install.sh | bash -s -- --update
    curl -fsSL https://install.faramesh.dev/install.sh | bash -s -- --no-interactive
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
                OS="linux"
                info "Detected Linux (WSL)"
            else
                OS="linux"
                info "Detected Linux"
            fi
            ;;
        Darwin*)
            OS="darwin"
            info "Detected macOS"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            info "Detected Windows (Bash)"
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
    RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")" \
        || die "Failed to fetch latest release. Check your network or pass --version explicitly."

    if command -v jq >/dev/null 2>&1; then
        VERSION="$(printf '%s' "${RELEASE_JSON}" | jq -r '.tag_name' | sed 's/^v//')"
    else
        VERSION="$(printf '%s\n' "${RELEASE_JSON}" \
            | grep '"tag_name"' \
            | head -n 1 \
            | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/')"
    fi

    [ -n "${VERSION}" ] || die "Failed to parse latest release tag from GitHub response."
fi

success "Version: ${VERSION}"

# ─── Download ───────────────────────────────────────────────────────────────────

step "Downloading faramesh v${VERSION}"

ASSET_FILE="faramesh-${OS}-${ARCH}"
if [ "${OS}" = "windows" ]; then
    ASSET_FILE="${ASSET_FILE}.exe"
    INSTALL_BINARY_NAME="${BINARY_NAME}.exe"
fi

CHECKSUM_FILE="${ASSET_FILE}.sha256"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET_FILE}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${CHECKSUM_FILE}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

info "Downloading ${DOWNLOAD_URL}"
curl -fSL --progress-bar -o "${TMPDIR}/${ASSET_FILE}" "${DOWNLOAD_URL}" \
    || die "Download failed. Is v${VERSION} a valid release?"

info "Downloading checksum manifest"
curl -fsSL -o "${TMPDIR}/${CHECKSUM_FILE}" "${CHECKSUM_URL}" \
    || die "Checksum manifest download failed."

# ─── Verify SHA-256 ─────────────────────────────────────────────────────────────

step "Verifying SHA-256 checksum"

EXPECTED_SHA=""
EXPECTED_SHA="$(awk 'NR==1 {print $1}' "${TMPDIR}/${CHECKSUM_FILE}")"

if [ -z "${EXPECTED_SHA}" ]; then
    die "Could not parse checksum from ${CHECKSUM_FILE}."
fi

if command -v sha256sum &>/dev/null; then
    ACTUAL_SHA="$(sha256sum "${TMPDIR}/${ASSET_FILE}" | awk '{print $1}')"
elif command -v shasum &>/dev/null; then
    ACTUAL_SHA="$(shasum -a 256 "${TMPDIR}/${ASSET_FILE}" | awk '{print $1}')"
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

if [ ! -f "${TMPDIR}/${ASSET_FILE}" ]; then
    die "Expected binary '${ASSET_FILE}' was not downloaded."
fi

chmod +x "${TMPDIR}/${ASSET_FILE}"

# ─── Install ────────────────────────────────────────────────────────────────────

step "Installing"

if [ "${UPDATE_MODE}" = true ]; then
    info "Update mode keeps caches, artifacts, logs, and runtime data in place; only the binary is replaced."
fi

existing_paths="$(discover_faramesh_paths)"
if [ -n "${existing_paths}" ]; then
    info "Searching for existing faramesh installs in PATH and common bin directories"
    printf '%s\n' "${existing_paths}" | while IFS= read -r found_path; do
        [ -n "${found_path}" ] || continue
        version_line="$("${found_path}" --version 2>/dev/null || true)"
        if [ -n "${version_line}" ]; then
            info "Found existing binary: ${found_path} (${version_line})"
        else
            info "Found existing binary: ${found_path}"
        fi
    done
fi

resolve_install_dir() {
    if [ -n "${INSTALL_DIR}" ]; then
        return
    fi

    local discovered_dir=""
    if discovered_dir="$(discover_install_dir)"; then
        INSTALL_DIR="${discovered_dir}"
        info "Detected existing faramesh install in ${INSTALL_DIR}; updating in place"
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

info "Installing to ${INSTALL_DIR}/${INSTALL_BINARY_NAME}"

if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMPDIR}/${ASSET_FILE}" "${INSTALL_DIR}/${INSTALL_BINARY_NAME}"
else
    warn "Elevated permissions required for ${INSTALL_DIR}"
    sudo mv "${TMPDIR}/${ASSET_FILE}" "${INSTALL_DIR}/${INSTALL_BINARY_NAME}"
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

INSTALLED_VERSION="$("${INSTALL_DIR}/${INSTALL_BINARY_NAME}" --version 2>&1)" \
    || die "Installed binary failed to execute."

success "faramesh ${INSTALLED_VERSION} installed successfully"

# ─── Interactive onboarding ─────────────────────────────────────────────────────

if [ "${INTERACTIVE}" = true ] && [ -t 0 ]; then
    step "Getting started"

    printf "${BOLD}Run the default first command now?${RESET} [Y/n] "
    read -r START_ANSWER </dev/tty
    START_ANSWER="${START_ANSWER:-Y}"
    if [[ "${START_ANSWER}" =~ ^[Yy]$ ]]; then
        printf "\n"
        "${INSTALL_DIR}/${INSTALL_BINARY_NAME}" init || warn "First command exited with non-zero status."
        printf "\n"
    fi
fi

# ─── Next steps ──────────────────────────────────────────────────────────────────

step "Next steps"

printf "  ${BOLD}Faramesh 2.0 quick path:${RESET}\n"
printf "     ${CYAN}1) faramesh init${RESET}\n"
printf "     ${CYAN}2) faramesh dev${RESET}\n"
printf "     ${CYAN}3) faramesh apply${RESET}\n"
printf "     ${CYAN}4) faramesh approvals${RESET}\n"
printf "     ${CYAN}5) faramesh explain <action-id>${RESET}\n"
printf "     ${CYAN}6) faramesh audit tail${RESET}\n"
printf "     ${CYAN}7) faramesh destroy${RESET}\n"
printf "     ${CYAN}8) bash scripts/faramesh_setup.sh update${RESET}\n"
printf "     ${CYAN}9) bash scripts/faramesh_setup.sh uninstall --binary-only${RESET}\n"
printf "    ${CYAN}10) bash scripts/faramesh_setup.sh uninstall --purge${RESET}\n"
printf "\n"
printf "  ${BOLD}Source checkout lifecycle:${RESET}\n"
printf "     ${CYAN}bash scripts/faramesh_setup.sh flow${RESET}\n"
printf "\n"
printf "  ${DIM}Documentation:${RESET}  ${BLUE}https://docs.faramesh.dev${RESET}\n"
printf "  ${DIM}GitHub:${RESET}         ${BLUE}https://github.com/${REPO}${RESET}\n"
printf "  ${DIM}Community:${RESET}      ${BLUE}https://discord.gg/faramesh${RESET}\n"
printf "\n"
success "Faramesh CLI is ready. Happy governing!"
printf "\n"
