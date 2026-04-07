#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STAGE_NAME="chain-exfil-stage"
POLICY_PATH=""
DURATION_SECONDS=300
METRICS_PORT=19190
SOCKET_PATH=""
TRAFFIC_CMD=""
DAEMON_CMD="${FARAMESH_DAEMON_CMD:-go run ./cmd/faramesh}"
EXTRA_SERVE_ARGS=""
RUN_DIR="${FARAMESH_CHAIN_EXFIL_RUN_DIR:-$CORE_DIR/.tmp/chain-exfil}"
REPORT_PATH=""
DATA_DIR=""
REPLAY_WAL=""
REPLAY_LIMIT=0
REPLAY_STRICT_REASON=false
REPLAY_TOOL_FILTER_REGEX="^(draft_email_with_body|proxy/http|read_customer_db|session/write)$"

MAX_SHADOW_EXPOSURE=1000000000
MAX_DENY_DELTA=1000000000
MAX_DEFER_DELTA=1000000000
MAX_REPLAY_DIVERGENCE=1000000000
MAX_REPLAY_DIVERGENCE_FILTERED=1000000000

DAEMON_PID=""
TRAFFIC_PID=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/chain_exfil_stage_gate.sh [options]

Options:
  --stage-name <name>              Stage label for logs and report.
  --policy <path>                  Policy file path.
  --duration <seconds>             Stage duration to observe metrics.
  --metrics-port <port>            Metrics endpoint port.
  --socket <path>                  SDK Unix socket path for this stage.
  --data-dir <path>                Daemon data dir for this stage.
  --traffic-cmd <command>          Optional traffic command executed during stage.
  --daemon-cmd <command>           Daemon command prefix (default: go run ./cmd/faramesh).
  --extra-serve-args <string>      Extra args appended to faramesh serve.
  --run-dir <path>                 Directory for logs and reports.
  --report <path>                  Output JSON report path.

Replay options:
  --replay-wal <path>              WAL file to replay (default: <data-dir>/faramesh.wal).
  --replay-limit <n>               Max replay records (0 = all).
  --strict-reason-parity           Enable strict reason parity replay mode.
  --replay-tool-filter-regex <re>  Regex for replay tool IDs that count toward filtered divergence gating.

Threshold gates:
  --max-shadow-exposure <n>        Max faramesh_shadow_mode_incident_exposure delta.
  --max-deny-delta <n>             Max faramesh_decisions_total{effect="deny"} delta.
  --max-defer-delta <n>            Max faramesh_decisions_total{effect="defer"} delta.
  --max-replay-divergence <n>      Max replay divergences allowed.
  --max-replay-divergence-filtered <n>
                                   Max replay divergences allowed after --replay-tool-filter-regex.

Example:
  bash scripts/chain_exfil_stage_gate.sh \
    --stage-name canary-shadow \
    --policy policies/chain_exfil_hardening.shadow.yaml \
    --replay-wal /data/prod/faramesh.wal \
    --traffic-cmd "bash tests/socket_e2e_acceptance.sh" \
    --duration 300 \
    --max-shadow-exposure 5 \
    --replay-tool-filter-regex '^(draft_email_with_body|proxy/http)$' \
    --max-replay-divergence-filtered 10 \
    --max-replay-divergence 20
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
      --policy)
        POLICY_PATH="$2"
        shift 2
        ;;
      --duration)
        DURATION_SECONDS="$2"
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
      --data-dir)
        DATA_DIR="$2"
        shift 2
        ;;
      --traffic-cmd)
        TRAFFIC_CMD="$2"
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
      --replay-wal)
        REPLAY_WAL="$2"
        shift 2
        ;;
      --replay-limit)
        REPLAY_LIMIT="$2"
        shift 2
        ;;
      --strict-reason-parity)
        REPLAY_STRICT_REASON=true
        shift
        ;;
      --replay-tool-filter-regex)
        REPLAY_TOOL_FILTER_REGEX="$2"
        shift 2
        ;;
      --max-shadow-exposure)
        MAX_SHADOW_EXPOSURE="$2"
        shift 2
        ;;
      --max-deny-delta)
        MAX_DENY_DELTA="$2"
        shift 2
        ;;
      --max-defer-delta)
        MAX_DEFER_DELTA="$2"
        shift 2
        ;;
      --max-replay-divergence)
        MAX_REPLAY_DIVERGENCE="$2"
        shift 2
        ;;
      --max-replay-divergence-filtered)
        MAX_REPLAY_DIVERGENCE_FILTERED="$2"
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

metric_value() {
  local file_path="$1"
  local metric_name="$2"
  awk -v metric="$metric_name" '
    BEGIN { sum = 0 }
    $1 == metric { sum += $2 }
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

if [[ -z "$POLICY_PATH" ]]; then
  echo "--policy is required" >&2
  exit 1
fi
if [[ ! -f "$POLICY_PATH" ]]; then
  echo "policy file not found: $POLICY_PATH" >&2
  exit 1
fi

require_int "$DURATION_SECONDS" "--duration"
require_int "$METRICS_PORT" "--metrics-port"
require_int "$REPLAY_LIMIT" "--replay-limit"
require_int "$MAX_SHADOW_EXPOSURE" "--max-shadow-exposure"
require_int "$MAX_DENY_DELTA" "--max-deny-delta"
require_int "$MAX_DEFER_DELTA" "--max-defer-delta"
require_int "$MAX_REPLAY_DIVERGENCE" "--max-replay-divergence"
require_int "$MAX_REPLAY_DIVERGENCE_FILTERED" "--max-replay-divergence-filtered"

mkdir -p "$RUN_DIR"
stage_slug="$(printf '%s' "$STAGE_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//')"
report_ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$SOCKET_PATH" ]]; then
  SOCKET_PATH="$RUN_DIR/${stage_slug}-${report_ts}.sock"
fi
if [[ -z "$DATA_DIR" ]]; then
  DATA_DIR="$RUN_DIR/${stage_slug}-${report_ts}.data"
fi
mkdir -p "$DATA_DIR"
if [[ -z "$REPORT_PATH" ]]; then
  REPORT_PATH="$RUN_DIR/${stage_slug}-${report_ts}.json"
fi

if [[ -z "$REPLAY_WAL" ]]; then
  REPLAY_WAL="$DATA_DIR/faramesh.wal"
fi

daemon_log="$RUN_DIR/${stage_slug}-${report_ts}.daemon.log"
traffic_log="$RUN_DIR/${stage_slug}-${report_ts}.traffic.log"
metrics_start="$RUN_DIR/${stage_slug}-${report_ts}.metrics.start.prom"
metrics_end="$RUN_DIR/${stage_slug}-${report_ts}.metrics.end.prom"
replay_log="$RUN_DIR/${stage_slug}-${report_ts}.replay.log"

read -r -a daemon_cmd_parts <<< "$DAEMON_CMD"
if [[ "${#daemon_cmd_parts[@]}" -eq 0 ]]; then
  echo "invalid --daemon-cmd" >&2
  exit 1
fi

serve_cmd=("${daemon_cmd_parts[@]}" serve
  --policy "$POLICY_PATH"
  --socket "$SOCKET_PATH"
  --data-dir "$DATA_DIR"
  --metrics-port "$METRICS_PORT"
)
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

shadow_start="$(metric_value "$metrics_start" "faramesh_shadow_mode_incident_exposure")"
shadow_end="$(metric_value "$metrics_end" "faramesh_shadow_mode_incident_exposure")"
deny_start="$(sum_metric "$metrics_start" "faramesh_decisions_total" 'effect="deny"' '' '')"
deny_end="$(sum_metric "$metrics_end" "faramesh_decisions_total" 'effect="deny"' '' '')"
defer_start="$(sum_metric "$metrics_start" "faramesh_decisions_total" 'effect="defer"' '' '')"
defer_end="$(sum_metric "$metrics_end" "faramesh_decisions_total" 'effect="defer"' '' '')"

shadow_delta=$((shadow_end - shadow_start))
deny_delta=$((deny_end - deny_start))
defer_delta=$((defer_end - defer_start))

status="PASS"
failed_checks=""
replay_status="SKIPPED"
replay_divergences=0
replay_divergences_filtered=0
replay_records=0
replay_exit=0

if (( shadow_delta > MAX_SHADOW_EXPOSURE )); then
  status="FAIL"
  failed_checks+="shadow_delta(${shadow_delta})>max(${MAX_SHADOW_EXPOSURE});"
fi
if (( deny_delta > MAX_DENY_DELTA )); then
  status="FAIL"
  failed_checks+="deny_delta(${deny_delta})>max(${MAX_DENY_DELTA});"
fi
if (( defer_delta > MAX_DEFER_DELTA )); then
  status="FAIL"
  failed_checks+="defer_delta(${defer_delta})>max(${MAX_DEFER_DELTA});"
fi

if [[ -f "$REPLAY_WAL" ]]; then
  replay_status="PASS"
  replay_cmd=("${daemon_cmd_parts[@]}" policy policy-replay
    --policy "$POLICY_PATH"
    --wal "$REPLAY_WAL"
    --limit "$REPLAY_LIMIT"
    --max-divergence "$MAX_REPLAY_DIVERGENCE"
  )
  if [[ "$REPLAY_STRICT_REASON" == "true" ]]; then
    replay_cmd+=(--strict-reason-parity)
  fi

  set +e
  (
    cd "$CORE_DIR"
    "${replay_cmd[@]}"
  ) >"$replay_log" 2>&1
  replay_exit=$?
  set -e

  summary_line="$(rg -m1 "policy replay:" "$replay_log" || true)"
  if [[ -n "$summary_line" ]]; then
    replay_records="$(echo "$summary_line" | sed -E 's/.*policy replay: ([0-9]+) record\(s\) examined,.*/\1/')"
    replay_divergences="$(echo "$summary_line" | sed -E 's/.* examined, ([0-9]+) divergence\(s\).*/\1/')"
  fi
  replay_divergences_filtered="$(awk -v re="$REPLAY_TOOL_FILTER_REGEX" '
    BEGIN { c = 0 }
    /^- record=/ {
      tool = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^tool=/) {
          tool = $i
          sub(/^tool=/, "", tool)
          break
        }
      }
      if (tool != "" && tool ~ re) {
        c++
      }
    }
    END { printf "%d", c }
  ' "$replay_log")"

  if (( replay_divergences > MAX_REPLAY_DIVERGENCE )); then
    status="FAIL"
    failed_checks+="replay_divergences(${replay_divergences})>max(${MAX_REPLAY_DIVERGENCE});"
  fi
  if (( replay_divergences_filtered > MAX_REPLAY_DIVERGENCE_FILTERED )); then
    status="FAIL"
    failed_checks+="replay_divergences_filtered(${replay_divergences_filtered})>max(${MAX_REPLAY_DIVERGENCE_FILTERED});"
  fi
  if (( replay_exit != 0 )); then
    replay_status="FAIL"
    status="FAIL"
    failed_checks+="policy_replay_exit(${replay_exit})!=0;"
  fi
else
  replay_status="MISSING_WAL"
  status="FAIL"
  failed_checks+="replay_wal_missing(${REPLAY_WAL});"
fi

cat > "$REPORT_PATH" <<EOF
{
  "stage": "$STAGE_NAME",
  "status": "$status",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "policy": "$POLICY_PATH",
  "duration_seconds": $DURATION_SECONDS,
  "ports": {
    "socket": "$SOCKET_PATH",
    "metrics": $METRICS_PORT
  },
  "thresholds": {
    "max_shadow_exposure": $MAX_SHADOW_EXPOSURE,
    "max_deny_delta": $MAX_DENY_DELTA,
    "max_defer_delta": $MAX_DEFER_DELTA,
    "max_replay_divergence": $MAX_REPLAY_DIVERGENCE,
    "max_replay_divergence_filtered": $MAX_REPLAY_DIVERGENCE_FILTERED
  },
  "deltas": {
    "shadow_exposure": $shadow_delta,
    "decisions_deny": $deny_delta,
    "decisions_defer": $defer_delta
  },
  "replay": {
    "status": "$replay_status",
    "wal": "$REPLAY_WAL",
    "records": $replay_records,
    "divergences": $replay_divergences,
    "divergences_filtered": $replay_divergences_filtered,
    "tool_filter_regex": "$REPLAY_TOOL_FILTER_REGEX",
    "strict_reason_parity": $REPLAY_STRICT_REASON,
    "exit_code": $replay_exit,
    "log": "$replay_log"
  },
  "failed_checks": "$failed_checks",
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
