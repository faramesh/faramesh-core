#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Compatibility wrapper.

Use the generic wizard directly:
  bash scripts/faramesh_govern_wizard.sh
EOF
fi

exec bash "$CORE_DIR/scripts/faramesh_govern_wizard.sh" "$@"
