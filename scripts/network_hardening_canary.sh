#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/network_hardening_canary.sh [options]

This is a wrapper around network_hardening_stage_gate.sh for audit-mode canary.

Common options:
  --policy <path>                 Policy file path (required).
  --duration <seconds>            Observation window (default: 300).
  --traffic-cmd <command>         Optional traffic command during canary.
  --proxy-port <port>             Proxy adapter port (default: 18080).
  --metrics-port <port>           Metrics endpoint port (default: 19090).
  --report <path>                 Report output path.
  --run-dir <path>                Artifact directory.

Threshold defaults:
  --max-audit-violations 50
  --max-audit-bypass 0
  --max-network-deny 0

Advanced:
  --socket <path>
  --allow-private-cidrs <csv>
  --allow-private-hosts <csv>
  --daemon-cmd <command>
  --extra-serve-args <string>

Example:
  bash scripts/network_hardening_canary.sh \
    --policy policies/default.fpl \
    --traffic-cmd "bash tests/socket_e2e_acceptance.sh" \
    --duration 300
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

exec bash "$CORE_DIR/scripts/network_hardening_stage_gate.sh" \
  --stage-name network-hardening-canary \
  --mode audit \
  --max-audit-violations 50 \
  --max-audit-bypass 0 \
  --max-network-deny 0 \
  "$@"
