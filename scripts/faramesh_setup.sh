#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Faramesh setup entrypoint.

Usage:
  bash scripts/faramesh_setup.sh [command] [args]

Commands:
  wizard         Start end-to-end governance wizard (default)
  status         Show wizard runtime status
  stop           Stop wizard runtime
  onboard        Run onboarding preflight wrapper
  offboard       Run automatic code offboarding (dry-run by default)
  install        Run binary installer script
  help           Show this help

Examples:
  bash scripts/faramesh_setup.sh
  bash scripts/faramesh_setup.sh wizard --yes --run-now no
  bash scripts/faramesh_setup.sh status
  bash scripts/faramesh_setup.sh stop
  bash scripts/faramesh_setup.sh onboard --policy policies/default.fpl
  bash scripts/faramesh_setup.sh offboard --path /path/to/agent --apply
  bash scripts/faramesh_setup.sh install --no-interactive
EOF
}

if [[ $# -eq 0 ]]; then
  exec bash "$CORE_DIR/scripts/faramesh_govern_wizard.sh"
fi

case "$1" in
  wizard)
    shift
    exec bash "$CORE_DIR/scripts/faramesh_govern_wizard.sh" "$@"
    ;;
  status|stop)
    cmd="$1"
    shift
    exec bash "$CORE_DIR/scripts/faramesh_govern_wizard.sh" "$cmd" "$@"
    ;;
  onboard)
    shift
    exec bash "$CORE_DIR/scripts/onboard.sh" "$@"
    ;;
  offboard)
    shift
    exec faramesh offboard "$@"
    ;;
  install)
    shift
    exec bash "$CORE_DIR/install.sh" "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  --*)
    exec bash "$CORE_DIR/scripts/faramesh_govern_wizard.sh" "$@"
    ;;
  *)
    echo "unknown command: $1" >&2
    usage
    exit 1
    ;;
esac