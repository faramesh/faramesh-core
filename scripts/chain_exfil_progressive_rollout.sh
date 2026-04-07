#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STAGE_FILE=""
TRAFFIC_CMD=""
RUN_DIR="${FARAMESH_CHAIN_EXFIL_RUN_DIR:-$CORE_DIR/.tmp/chain-exfil/rollout}"
METRICS_PORT_BASE=19190
DAEMON_CMD=""
EXTRA_SERVE_ARGS=""
REPLAY_LIMIT=0
REPLAY_STRICT_REASON=false
REPLAY_WAL_DEFAULT="${FARAMESH_CHAIN_EXFIL_REPLAY_WAL:-}"
REPLAY_TOOL_FILTER_REGEX=""
MAX_REPLAY_DIVERGENCE_FILTERED_DEFAULT="1000000000"
CONTINUE_ON_FAIL=false

usage() {
  cat <<'EOF'
Usage:
  bash scripts/chain_exfil_progressive_rollout.sh --stage-file <path> [options]

Runs a sequence of chain-exfil rollout stages using chain_exfil_stage_gate.sh.

Required:
  --stage-file <path>             CSV file with rollout stages.

Optional:
  --traffic-cmd <command>         Traffic generator command applied to all stages.
  --run-dir <path>                Artifacts directory.
  --metrics-port-base <port>      Base metrics port (stage index increments by 10).
  --daemon-cmd <command>          Override daemon command prefix.
  --extra-serve-args <string>     Extra args appended to faramesh serve.
  --replay-limit <n>              Max replay records per stage (0 = all).
  --strict-reason-parity          Enable strict reason parity for replay.
  --replay-wal-default <path>     Default WAL path used when stage replay_wal is empty or @default.
  --replay-tool-filter-regex <re> Regex for replay tool IDs used by stage gate filtered divergence.
  --max-replay-divergence-filtered-default <n>
                                  Default filtered divergence cap when stage value is empty.
  --continue-on-fail              Keep running all stages even if one fails.

Stage file format (CSV):
  name,policy,duration,max_shadow_exposure,max_deny_delta,max_defer_delta,replay_wal,max_replay_divergence,max_replay_divergence_filtered

Example:
  canary-shadow,policies/chain_exfil_hardening.shadow.yaml,300,5,100,100,@default,30,10
  staging-enforce-10,policies/chain_exfil_hardening.yaml,300,0,120,120,@default,20,8
  prod-enforce-100,policies/chain_exfil_hardening.yaml,600,0,150,150,@default,10,5
EOF
}

require_int() {
  local value="$1"
  local label="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$label must be a non-negative integer, got: $value" >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stage-file)
        STAGE_FILE="$2"
        shift 2
        ;;
      --traffic-cmd)
        TRAFFIC_CMD="$2"
        shift 2
        ;;
      --run-dir)
        RUN_DIR="$2"
        shift 2
        ;;
      --metrics-port-base)
        METRICS_PORT_BASE="$2"
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
      --replay-limit)
        REPLAY_LIMIT="$2"
        shift 2
        ;;
      --strict-reason-parity)
        REPLAY_STRICT_REASON=true
        shift
        ;;
      --replay-wal-default)
        REPLAY_WAL_DEFAULT="$2"
        shift 2
        ;;
      --replay-tool-filter-regex)
        REPLAY_TOOL_FILTER_REGEX="$2"
        shift 2
        ;;
      --max-replay-divergence-filtered-default)
        MAX_REPLAY_DIVERGENCE_FILTERED_DEFAULT="$2"
        shift 2
        ;;
      --continue-on-fail)
        CONTINUE_ON_FAIL=true
        shift
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

parse_args "$@"

if [[ -z "$STAGE_FILE" ]]; then
  echo "--stage-file is required" >&2
  usage >&2
  exit 1
fi
if [[ ! -f "$STAGE_FILE" ]]; then
  echo "stage file not found: $STAGE_FILE" >&2
  exit 1
fi

require_int "$METRICS_PORT_BASE" "--metrics-port-base"
require_int "$REPLAY_LIMIT" "--replay-limit"
require_int "$MAX_REPLAY_DIVERGENCE_FILTERED_DEFAULT" "--max-replay-divergence-filtered-default"

mkdir -p "$RUN_DIR"
summary_path="$RUN_DIR/summary-$(date -u +%Y%m%dT%H%M%SZ).txt"

echo "Chain exfil progressive rollout" | tee -a "$summary_path"
echo "stage_file=$STAGE_FILE" | tee -a "$summary_path"
echo "run_dir=$RUN_DIR" | tee -a "$summary_path"
echo | tee -a "$summary_path"

stage_index=0
failed_count=0

while IFS=',' read -r raw_name raw_policy raw_duration raw_max_shadow raw_max_deny raw_max_defer raw_replay_wal raw_max_replay raw_max_replay_filtered; do
  name="$(echo "${raw_name:-}" | xargs)"
  policy="$(echo "${raw_policy:-}" | xargs)"
  duration="$(echo "${raw_duration:-}" | xargs)"
  max_shadow="$(echo "${raw_max_shadow:-}" | xargs)"
  max_deny="$(echo "${raw_max_deny:-}" | xargs)"
  max_defer="$(echo "${raw_max_defer:-}" | xargs)"
  replay_wal="$(echo "${raw_replay_wal:-}" | xargs)"
  max_replay="$(echo "${raw_max_replay:-}" | xargs)"
  max_replay_filtered="$(echo "${raw_max_replay_filtered:-}" | xargs)"

  if [[ -z "$name" ]]; then
    continue
  fi
  if [[ "${name:0:1}" == "#" ]]; then
    continue
  fi
  if [[ "$name" == "name" && "$policy" == "policy" ]]; then
    continue
  fi

  if [[ -z "$policy" || -z "$duration" || -z "$max_shadow" || -z "$max_deny" || -z "$max_defer" || -z "$max_replay" ]]; then
    echo "invalid stage row (missing required fields): $name" | tee -a "$summary_path"
    failed_count=$((failed_count + 1))
    if [[ "$CONTINUE_ON_FAIL" != "true" ]]; then
      break
    fi
    continue
  fi

  if [[ -z "$max_replay_filtered" ]]; then
    max_replay_filtered="$MAX_REPLAY_DIVERGENCE_FILTERED_DEFAULT"
  fi
  if [[ "$replay_wal" == "@default" || -z "$replay_wal" ]]; then
    replay_wal="$REPLAY_WAL_DEFAULT"
  fi
  if [[ -z "$replay_wal" ]]; then
    echo "stage '$name' has no replay_wal and no --replay-wal-default configured" | tee -a "$summary_path"
    failed_count=$((failed_count + 1))
    if [[ "$CONTINUE_ON_FAIL" != "true" ]]; then
      break
    fi
    continue
  fi

  require_int "$duration" "duration($name)"
  require_int "$max_shadow" "max_shadow_exposure($name)"
  require_int "$max_deny" "max_deny_delta($name)"
  require_int "$max_defer" "max_defer_delta($name)"
  require_int "$max_replay" "max_replay_divergence($name)"
  require_int "$max_replay_filtered" "max_replay_divergence_filtered($name)"

  metrics_port=$((METRICS_PORT_BASE + stage_index * 10))
  stage_slug="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//')"
  report_path="$RUN_DIR/${stage_slug}.json"

  cmd=(bash "$CORE_DIR/scripts/chain_exfil_stage_gate.sh"
    --stage-name "$name"
    --policy "$policy"
    --duration "$duration"
    --metrics-port "$metrics_port"
    --max-shadow-exposure "$max_shadow"
    --max-deny-delta "$max_deny"
    --max-defer-delta "$max_defer"
    --max-replay-divergence "$max_replay"
    --max-replay-divergence-filtered "$max_replay_filtered"
    --replay-limit "$REPLAY_LIMIT"
    --run-dir "$RUN_DIR"
    --report "$report_path"
  )

  if [[ -n "$TRAFFIC_CMD" ]]; then
    cmd+=(--traffic-cmd "$TRAFFIC_CMD")
  fi
  if [[ -n "$DAEMON_CMD" ]]; then
    cmd+=(--daemon-cmd "$DAEMON_CMD")
  fi
  if [[ -n "$EXTRA_SERVE_ARGS" ]]; then
    cmd+=(--extra-serve-args "$EXTRA_SERVE_ARGS")
  fi
  if [[ -n "$replay_wal" ]]; then
    cmd+=(--replay-wal "$replay_wal")
  fi
  if [[ -n "$REPLAY_TOOL_FILTER_REGEX" ]]; then
    cmd+=(--replay-tool-filter-regex "$REPLAY_TOOL_FILTER_REGEX")
  fi
  if [[ "$REPLAY_STRICT_REASON" == "true" ]]; then
    cmd+=(--strict-reason-parity)
  fi

  echo "running stage=$name policy=$policy duration=${duration}s" | tee -a "$summary_path"
  if "${cmd[@]}"; then
    echo "stage=$name result=PASS report=$report_path" | tee -a "$summary_path"
  else
    echo "stage=$name result=FAIL report=$report_path" | tee -a "$summary_path"
    failed_count=$((failed_count + 1))
    if [[ "$CONTINUE_ON_FAIL" != "true" ]]; then
      break
    fi
  fi

  stage_index=$((stage_index + 1))
  echo | tee -a "$summary_path"
done < "$STAGE_FILE"

echo "summary=$summary_path"

if (( failed_count > 0 )); then
  echo "progressive rollout failed stages=$failed_count" >&2
  exit 2
fi

echo "progressive rollout passed"
