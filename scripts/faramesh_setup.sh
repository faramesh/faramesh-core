#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIZARD_SCRIPT="$CORE_DIR/scripts/faramesh_govern_wizard.sh"
SETUP_CACHE_DIR="${FARAMESH_SETUP_CACHE_DIR:-$CORE_DIR/.tmp/faramesh-setup}"
LOCAL_BUILD_BIN="$SETUP_CACHE_DIR/faramesh"

normalize_yes_no() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    y|yes|true|1)
      echo "yes"
      ;;
    n|no|false|0)
      echo "no"
      ;;
    *)
      echo ""
      ;;
  esac
}

normalize_bool_for_cobra() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    y|yes|true|1|t)
      echo "true"
      ;;
    n|no|false|0|f)
      echo "false"
      ;;
    *)
      echo "$1"
      ;;
  esac
}

has_flag_prefix() {
  local prefix="$1"
  shift || true
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$prefix" || "$arg" == "$prefix="* ]]; then
      return 0
    fi
  done
  return 1
}

binary_supports_subcommand() {
  local bin="$1"
  local required_subcommand="${2:-}"
  if [[ -z "$required_subcommand" ]]; then
    return 0
  fi
  "$bin" help "$required_subcommand" >/dev/null 2>&1
}

resolve_faramesh_bin() {
  local required_subcommand="${1:-}"

  if [[ -n "${FARAMESH_SETUP_BIN:-}" ]] && [[ -x "${FARAMESH_SETUP_BIN}" ]]; then
    if binary_supports_subcommand "$FARAMESH_SETUP_BIN" "$required_subcommand"; then
      echo "$FARAMESH_SETUP_BIN"
      return 0
    fi
  fi

  if [[ -x "$LOCAL_BUILD_BIN" ]] && binary_supports_subcommand "$LOCAL_BUILD_BIN" "$required_subcommand"; then
    echo "$LOCAL_BUILD_BIN"
    return 0
  fi

  local candidate=""
  if type -P faramesh >/dev/null 2>&1; then
    candidate="$(type -P faramesh)"
  elif command -v faramesh >/dev/null 2>&1; then
    candidate="$(command -v faramesh)"
  fi

  if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then
    if binary_supports_subcommand "$candidate" "$required_subcommand"; then
      echo "$candidate"
      return 0
    fi
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo "no compatible faramesh binary found and Go is unavailable to build a local copy" >&2
    echo "run: bash scripts/faramesh_setup.sh install" >&2
    exit 1
  fi

  mkdir -p "$SETUP_CACHE_DIR"
  (
    cd "$CORE_DIR"
    go build -o "$LOCAL_BUILD_BIN" ./cmd/faramesh
  )

  if ! binary_supports_subcommand "$LOCAL_BUILD_BIN" "$required_subcommand"; then
    echo "built faramesh binary does not support required subcommand: $required_subcommand" >&2
    exit 1
  fi

  echo "$LOCAL_BUILD_BIN"
}

confirm_or_exit() {
  local prompt="$1"
  local answer=""
  read -r -p "$prompt [y/N]: " answer || true
  answer="$(normalize_yes_no "${answer:-no}")"
  if [[ "$answer" != "yes" ]]; then
    echo "aborted"
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Faramesh lifecycle manager (canonical setup command).

Usage:
  bash scripts/faramesh_setup.sh [command] [args]

Commands:
  start|wizard   Start governance wizard (default)
  status         Show wizard runtime status
  stop           Stop wizard runtime
  onboard        Run onboarding preflight with strict defaults
  offboard       Run automatic code offboarding (dry-run by default)
  uninstall      Detach Faramesh from project(s), stop runtime, remove local installs
  install        Run binary installer script
  help           Show this help

Examples:
  bash scripts/faramesh_setup.sh
  bash scripts/faramesh_setup.sh start --framework langchain --agent-cmd "python app.py"
  bash scripts/faramesh_setup.sh status
  bash scripts/faramesh_setup.sh stop
  bash scripts/faramesh_setup.sh onboard --policy policies/default.fpl --credential-profile production
  bash scripts/faramesh_setup.sh offboard --path /path/to/agent --apply
  bash scripts/faramesh_setup.sh uninstall --path /path/to/agent --yes
  bash scripts/faramesh_setup.sh install --no-interactive

Recommended flow for existing agent stacks (LangChain, LangGraph, DeepAgents, MCP):
  1) install:    bash scripts/faramesh_setup.sh install
  2) govern:     bash scripts/faramesh_setup.sh start
  3) stop:       bash scripts/faramesh_setup.sh stop
  4) detach:     bash scripts/faramesh_setup.sh offboard --path <agent-project> --apply
  5) uninstall:  bash scripts/faramesh_setup.sh uninstall --path <agent-project> --yes
EOF
}

uninstall_usage() {
  cat <<'EOF'
Usage:
  bash scripts/faramesh_setup.sh uninstall [options]

Options:
  --path <dir>                Project path to detach with offboard (repeatable)
  --backup-ext <ext>          Backup extension for offboard rewrites (default: .faramesh.bak)
  --remove-generated <yes|no> Remove generated faramesh/policy files (default: yes)
  --skip-offboard             Do not run project detachment
  --yes, -y                   Skip confirmation prompt
  -h, --help                  Show this help

Examples:
  bash scripts/faramesh_setup.sh uninstall --path ./my-agent
  bash scripts/faramesh_setup.sh uninstall --path ./agent-a --path ./agent-b --yes
  bash scripts/faramesh_setup.sh uninstall --skip-offboard --yes
EOF
}

remove_binary_if_present() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    return 0
  fi
  if [[ -w "$target" || -w "$(dirname "$target")" ]]; then
    rm -f "$target"
    echo "removed binary: $target"
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo rm -f "$target"
    echo "removed binary (sudo): $target"
    return 0
  fi
  echo "could not remove binary (permission denied): $target" >&2
  return 1
}

run_onboard() {
  local bin
  bin="$(resolve_faramesh_bin onboard)"

  local strict_default
  strict_default="$(normalize_bool_for_cobra "${FARAMESH_ONBOARD_STRICT:-true}")"
  local policy_default="${FARAMESH_POLICY_PATH:-}"
  local -a args
  args=("$@")

  local i=0
  for ((i = 0; i < ${#args[@]}; i++)); do
    if [[ "${args[$i]}" == --strict=* ]]; then
      args[$i]="--strict=$(normalize_bool_for_cobra "${args[$i]#--strict=}")"
    elif [[ "${args[$i]}" == "--strict" ]] && (( i + 1 < ${#args[@]} )); then
      args[$((i + 1))]="$(normalize_bool_for_cobra "${args[$((i + 1))]}")"
    fi
  done

  if ! has_flag_prefix "--strict" "${args[@]}"; then
    args=(--strict="$strict_default" "${args[@]}")
  fi
  if [[ -n "$policy_default" ]] && ! has_flag_prefix "--policy" "${args[@]}"; then
    args=(--policy "$policy_default" "${args[@]}")
  fi

  exec "$bin" onboard "${args[@]}"
}

run_offboard() {
  local bin
  bin="$(resolve_faramesh_bin offboard)"
  exec "$bin" offboard "$@"
}

run_uninstall() {
  local assume_yes=0
  local skip_offboard="no"
  local remove_generated="yes"
  local backup_ext=".faramesh.bak"
  local -a project_paths=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        project_paths+=("${2:-}")
        shift
        ;;
      --backup-ext)
        backup_ext="${2:-}"
        shift
        ;;
      --remove-generated)
        remove_generated="${2:-}"
        shift
        ;;
      --skip-offboard)
        skip_offboard="yes"
        ;;
      --yes|-y)
        assume_yes=1
        ;;
      -h|--help)
        uninstall_usage
        exit 0
        ;;
      *)
        echo "unknown uninstall option: $1" >&2
        uninstall_usage
        exit 1
        ;;
    esac
    shift
  done

  remove_generated="$(normalize_yes_no "$remove_generated")"
  if [[ -z "$remove_generated" ]]; then
    echo "invalid --remove-generated value (expected yes|no)" >&2
    exit 1
  fi

  if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -eq 0 ]]; then
    echo "no --path supplied; project code detach will be skipped"
  fi

  if [[ "$assume_yes" -eq 0 ]]; then
    echo "this will:"
    echo "  1) stop wizard-managed Faramesh runtime"
    if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -gt 0 ]]; then
      echo "  2) apply offboard rewrites for provided project path(s)"
    fi
    echo "  3) remove setup-local runtime state"
    echo "  4) remove common local faramesh binaries when present"
    confirm_or_exit "continue uninstall"
  fi

  if [[ "$skip_offboard" == "no" ]] && [[ ${#project_paths[@]} -gt 0 ]]; then
    local bin
    bin="$(resolve_faramesh_bin offboard)"
    local path
    for path in "${project_paths[@]}"; do
      if [[ -z "$path" ]]; then
        continue
      fi
      local -a offboard_cmd
      offboard_cmd=(offboard --path "$path" --apply --backup-ext "$backup_ext")
      if [[ "$remove_generated" == "yes" ]]; then
        offboard_cmd+=(--remove-generated)
      fi
      "$bin" "${offboard_cmd[@]}"
    done
  fi

  bash "$WIZARD_SCRIPT" stop >/dev/null 2>&1 || true

  rm -rf "${FARAMESH_WIZARD_DIR:-$CORE_DIR/.tmp/faramesh-wizard}"
  rm -f "$LOCAL_BUILD_BIN"

  remove_binary_if_present "/usr/local/bin/faramesh" || true
  remove_binary_if_present "$HOME/.local/bin/faramesh" || true

  local detected_bin=""
  if type -P faramesh >/dev/null 2>&1; then
    detected_bin="$(type -P faramesh)"
  elif command -v faramesh >/dev/null 2>&1; then
    detected_bin="$(command -v faramesh)"
  fi

  if [[ -n "$detected_bin" ]] && [[ -x "$detected_bin" ]]; then
    case "$detected_bin" in
      /opt/homebrew/*|/usr/local/Cellar/*)
        echo "homebrew-managed faramesh detected at $detected_bin"
        echo "run: brew uninstall faramesh/tap/faramesh"
        ;;
      *)
        if [[ "$detected_bin" != "/usr/local/bin/faramesh" && "$detected_bin" != "$HOME/.local/bin/faramesh" ]]; then
          echo "additional faramesh binary still on PATH: $detected_bin"
          echo "remove it manually if you want full uninstall"
        fi
        ;;
    esac
  fi

  echo "uninstall flow complete"
}

if [[ $# -eq 0 ]]; then
  exec bash "$WIZARD_SCRIPT"
fi

case "$1" in
  start|wizard)
    shift
    exec bash "$WIZARD_SCRIPT" "$@"
    ;;
  status|stop)
    cmd="$1"
    shift
    exec bash "$WIZARD_SCRIPT" "$cmd" "$@"
    ;;
  onboard)
    shift
    run_onboard "$@"
    ;;
  offboard|detach)
    shift
    run_offboard "$@"
    ;;
  uninstall)
    shift
    run_uninstall "$@"
    ;;
  install)
    shift
    exec bash "$CORE_DIR/install.sh" "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  --*)
    exec bash "$WIZARD_SCRIPT" "$@"
    ;;
  *)
    echo "unknown command: $1" >&2
    usage
    exit 1
    ;;
esac