#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STAGE_NAME="network-hardening-stage"
MODE="audit"
POLICY_PATH=""
DURATION_SECONDS=300
PROXY_PORT=18080
METRICS_PORT=19090
SOCKET_PATH=""
TRAFFIC_CMD=""
ALLOW_PRIVATE_CIDRS=""
ALLOW_PRIVATE_HOSTS=""
DAEMON_CMD="${FARAMESH_DAEMON_CMD:-go run ./cmd/faramesh}"
EXTRA_SERVE_ARGS=""
RUN_DIR="${FARAMESH_NETWORK_HARDENING_RUN_DIR:-$CORE_DIR/.tmp/network-hardening}"
REPORT_PATH=""

MAX_AUDIT_VIOLATIONS=1000000000
MAX_AUDIT_BYPASS=1000000000
MAX_NETWORK_DENY=1000000000

DAEMON_PID=""
TRAFFIC_PID=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/network_hardening_stage_gate.sh [options]

Options:
  --stage-name <name>             Stage label for logs and report.
  --mode <audit|enforce>          Hardening mode for this stage.
  --policy <path>                 Policy file path.
  --duration <seconds>            Stage duration to observe metrics.
  --proxy-port <port>             Proxy adapter port.
  --metrics-port <port>           Metrics endpoint port.
  --socket <path>                 SDK Unix socket path for this stage.
  --traffic-cmd <command>         Optional traffic command executed during stage.
  --allow-private-cidrs <csv>     Pass-through allowlist for private CIDRs.
  --allow-private-hosts <csv>     Pass-through allowlist for private hosts.
  --daemon-cmd <command>          Daemon command prefix (default: go run ./cmd/faramesh).
  --extra-serve-args <string>     Extra args appended to faramesh serve.
  --run-dir <path>                Directory for logs and reports.
  --report <path>                 Output JSON report path.

Threshold gates:
  --max-audit-violations <n>      Max audit_violation delta allowed.
  --max-audit-bypass <n>          Max audit_bypass delta allowed.
  --max-network-deny <n>          Max hardening deny delta allowed.

Examples:
  bash scripts/network_hardening_stage_gate.sh \
    --stage-name canary-audit \
    --mode audit \
    --policy policies/default.fpl \
    --traffic-cmd "bash tests/socket_e2e_acceptance.sh" \
    --duration 300 \
    --max-audit-bypass 0
EOF
}

cleanup() {
  if [[ -n "$TRAFFIC_PID" ]] && kill -0 "$TRAFFIC_PID" >/dev/null 2>&1; then
    kill "$TRAFFIC_PID" >/dev/null 2>&1 || true
    wait "$TRAFFIC_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stage-name)
        STAGE_NAME="$2"
        shift 2
        ;;
      --mode)
        MODE="$2"
        shift 2
        ;;
      --policy)
        POLICY_PATH="$2"
        shift 2
        ;;
      --duration)
        DURATION_SECONDS="$2"
        shift 2
        ;;
      --proxy-port)
        PROXY_PORT="$2"
        shift 2
        ;;
      --metrics-port)
        METRICS_PORT="$2"
        shift 2
        ;;
      --socket)
        SOCKET_PATH="$2"
        shift 2
        ;;
      --traffic-cmd)
        TRAFFIC_CMD="$2"
        shift 2
        ;;
      --allow-private-cidrs)
        ALLOW_PRIVATE_CIDRS="$2"
        shift 2
        ;;
      --allow-private-hosts)
        ALLOW_PRIVATE_HOSTS="$2"
        shift 2
        ;;
      --daemon-cmd)
        DAEMON_CMD="$2"
        shift 2
        ;;
      --extra-serve-args)
        EXTRA_SERVE_ARGS="$2"
        shift 2
        ;;
      --run-dir)
        RUN_DIR="$2"
        shift 2
        ;;
      --report)
        REPORT_PATH="$2"
        shift 2
        ;;
      --max-audit-violations)
        MAX_AUDIT_VIOLATIONS="$2"
        shift 2
        ;;
      --max-audit-bypass)
        MAX_AUDIT_BYPASS="$2"
        shift 2
        ;;
      --max-network-deny)
        MAX_NETWORK_DENY="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

require_int() {
  local value="$1"
  local label="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$label must be a non-negative integer, got: $value" >&2
    exit 1
  fi
}

sum_metric() {
  local file_path="$1"
  local metric_name="$2"
  local filter_a="$3"
  local filter_b="$4"
  local filter_c="$5"

  awk -v metric="$metric_name" -v a="$filter_a" -v b="$filter_b" -v c="$filter_c" '
    BEGIN { sum = 0 }
    $0 ~ "^" metric "\\{" {
      if ((a == "" || index($0, a) > 0) && (b == "" || index($0, b) > 0) && (c == "" || index($0, c) > 0)) {
        sum += $NF
      }
    }
    END { printf "%.0f", sum }
  ' "$file_path"
}

fetch_metrics() {
  local out_path="$1"
  curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" > "$out_path"
}

wait_for_metrics() {
  local attempts=180
  local delay=0.25

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "$DAEMON_PID" ]] && ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
      return 1
    fi
    sleep "$delay"
  done

  return 1
}

parse_args "$@"

MODE="$(echo "$MODE" | tr '[:upper:]' '[:lower:]')"
if [[ "$MODE" != "audit" && "$MODE" != "enforce" ]]; then
  echo "--mode must be audit or enforce" >&2
  exit 1
fi

if [[ -z "$POLICY_PATH" ]]; then
  echo "--policy is required" >&2
  exit 1
fi

require_int "$DURATION_SECONDS" "--duration"
require_int "$PROXY_PORT" "--proxy-port"
require_int "$METRICS_PORT" "--metrics-port"
require_int "$MAX_AUDIT_VIOLATIONS" "--max-audit-violations"
require_int "$MAX_AUDIT_BYPASS" "--max-audit-bypass"
require_int "$MAX_NETWORK_DENY" "--max-network-deny"

mkdir -p "$RUN_DIR"
slug_stage="$(printf '%s' "$STAGE_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//')"
report_ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$REPORT_PATH" ]]; then
  REPORT_PATH="$RUN_DIR/${slug_stage}-${report_ts}.json"
fi

daemon_log="$RUN_DIR/${slug_stage}-${report_ts}.daemon.log"
traffic_log="$RUN_DIR/${slug_stage}-${report_ts}.traffic.log"
metrics_start="$RUN_DIR/${slug_stage}-${report_ts}.metrics.start.prom"
metrics_end="$RUN_DIR/${slug_stage}-${report_ts}.metrics.end.prom"

if [[ -z "$SOCKET_PATH" ]]; then
  SOCKET_PATH="$RUN_DIR/${slug_stage}-${report_ts}.sock"
fi

read -r -a daemon_cmd_parts <<< "$DAEMON_CMD"
if [[ "${#daemon_cmd_parts[@]}" -eq 0 ]]; then
  echo "invalid --daemon-cmd" >&2
  exit 1
fi

serve_cmd=("${daemon_cmd_parts[@]}" serve
  --policy "$POLICY_PATH"
  --socket "$SOCKET_PATH"
  --proxy-port "$PROXY_PORT"
  --proxy-forward
  --network-hardening-mode "$MODE"
  --metrics-port "$METRICS_PORT"
)

if [[ -n "$ALLOW_PRIVATE_CIDRS" ]]; then
  serve_cmd+=(--allow-private-cidrs "$ALLOW_PRIVATE_CIDRS")
fi
if [[ -n "$ALLOW_PRIVATE_HOSTS" ]]; then
  serve_cmd+=(--allow-private-hosts "$ALLOW_PRIVATE_HOSTS")
fi
if [[ -n "$EXTRA_SERVE_ARGS" ]]; then
  read -r -a extra_serve_parts <<< "$EXTRA_SERVE_ARGS"
  serve_cmd+=("${extra_serve_parts[@]}")
fi

(
  cd "$CORE_DIR"
  "${serve_cmd[@]}"
) >"$daemon_log" 2>&1 &
DAEMON_PID="$!"

if ! wait_for_metrics; then
  echo "failed to start daemon or metrics endpoint" >&2
  tail -n 120 "$daemon_log" >&2 || true
  exit 2
fi

fetch_metrics "$metrics_start"

if [[ -n "$TRAFFIC_CMD" ]]; then
  (
    cd "$CORE_DIR"
    bash -lc "$TRAFFIC_CMD"
  ) >"$traffic_log" 2>&1 &
  TRAFFIC_PID="$!"
fi

sleep "$DURATION_SECONDS"

if [[ -n "$TRAFFIC_PID" ]] && kill -0 "$TRAFFIC_PID" >/dev/null 2>&1; then
  kill "$TRAFFIC_PID" >/dev/null 2>&1 || true
  wait "$TRAFFIC_PID" >/dev/null 2>&1 || true
fi

fetch_metrics "$metrics_end"

audit_violations_start="$(sum_metric "$metrics_start" "faramesh_network_hardening_total" 'mode="audit"' 'outcome="audit_violation"' '')"
audit_violations_end="$(sum_metric "$metrics_end" "faramesh_network_hardening_total" 'mode="audit"' 'outcome="audit_violation"' '')"
audit_bypass_start="$(sum_metric "$metrics_start" "faramesh_network_hardening_total" 'mode="audit"' 'outcome="audit_bypass"' '')"
audit_bypass_end="$(sum_metric "$metrics_end" "faramesh_network_hardening_total" 'mode="audit"' 'outcome="audit_bypass"' '')"
network_deny_start="$(sum_metric "$metrics_start" "faramesh_network_hardening_total" "mode=\"$MODE\"" 'outcome="deny"' '')"
network_deny_end="$(sum_metric "$metrics_end" "faramesh_network_hardening_total" "mode=\"$MODE\"" 'outcome="deny"' '')"

decisions_permit_start="$(sum_metric "$metrics_start" "faramesh_decisions_total" 'effect="permit"' '' '')"
decisions_permit_end="$(sum_metric "$metrics_end" "faramesh_decisions_total" 'effect="permit"' '' '')"
decisions_deny_start="$(sum_metric "$metrics_start" "faramesh_decisions_total" 'effect="deny"' '' '')"
decisions_deny_end="$(sum_metric "$metrics_end" "faramesh_decisions_total" 'effect="deny"' '' '')"

audit_violations_delta=$((audit_violations_end - audit_violations_start))
audit_bypass_delta=$((audit_bypass_end - audit_bypass_start))
network_deny_delta=$((network_deny_end - network_deny_start))
decisions_permit_delta=$((decisions_permit_end - decisions_permit_start))
decisions_deny_delta=$((decisions_deny_end - decisions_deny_start))

status="PASS"
failed_checks=""

if (( audit_violations_delta > MAX_AUDIT_VIOLATIONS )); then
  status="FAIL"
  failed_checks+="audit_violations_delta(${audit_violations_delta})>max(${MAX_AUDIT_VIOLATIONS});"
fi
if (( audit_bypass_delta > MAX_AUDIT_BYPASS )); then
  status="FAIL"
  failed_checks+="audit_bypass_delta(${audit_bypass_delta})>max(${MAX_AUDIT_BYPASS});"
fi
if (( network_deny_delta > MAX_NETWORK_DENY )); then
  status="FAIL"
  failed_checks+="network_deny_delta(${network_deny_delta})>max(${MAX_NETWORK_DENY});"
fi

cat > "$REPORT_PATH" <<EOF
{
  "stage": "$STAGE_NAME",
  "mode": "$MODE",
  "status": "$status",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $DURATION_SECONDS,
  "ports": {
    "socket": "$SOCKET_PATH",
    "proxy": $PROXY_PORT,
    "metrics": $METRICS_PORT
  },
  "thresholds": {
    "max_audit_violations": $MAX_AUDIT_VIOLATIONS,
    "max_audit_bypass": $MAX_AUDIT_BYPASS,
    "max_network_deny": $MAX_NETWORK_DENY
  },
  "deltas": {
    "audit_violations": $audit_violations_delta,
    "audit_bypass": $audit_bypass_delta,
    "network_deny": $network_deny_delta,
    "decisions_permit": $decisions_permit_delta,
    "decisions_deny": $decisions_deny_delta
  },
  "failed_checks": "${failed_checks}",
  "artifacts": {
    "daemon_log": "$daemon_log",
    "traffic_log": "$traffic_log",
    "metrics_start": "$metrics_start",
    "metrics_end": "$metrics_end"
  }
}
EOF

echo "stage report: $REPORT_PATH"
echo "stage status: $status"

if [[ "$status" != "PASS" ]]; then
  exit 2
fi
