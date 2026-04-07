#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STAGE_FILE=""
TRAFFIC_CMD=""
RUN_DIR="${FARAMESH_NETWORK_HARDENING_RUN_DIR:-$CORE_DIR/.tmp/network-hardening/rollout}"
PROXY_PORT_BASE=18080
METRICS_PORT_BASE=19090
ALLOW_PRIVATE_CIDRS=""
ALLOW_PRIVATE_HOSTS=""
DAEMON_CMD=""
EXTRA_SERVE_ARGS=""
CONTINUE_ON_FAIL=false

usage() {
  cat <<'EOF'
Usage:
  bash scripts/network_hardening_progressive_rollout.sh --stage-file <path> [options]

Runs a sequence of audit/enforce rollout stages using network_hardening_stage_gate.sh.

Required:
  --stage-file <path>             CSV file with rollout stages.

Optional:
  --traffic-cmd <command>         Traffic generator command applied to all stages.
  --run-dir <path>                Artifacts directory.
  --proxy-port-base <port>        Base proxy port (stage index increments by 10).
  --metrics-port-base <port>      Base metrics port (stage index increments by 10).
  --allow-private-cidrs <csv>     Pass-through allowlist for private CIDRs.
  --allow-private-hosts <csv>     Pass-through allowlist for private hosts.
  --daemon-cmd <command>          Override daemon command prefix.
  --extra-serve-args <string>     Extra args appended to faramesh serve.
  --continue-on-fail              Keep running all stages even if one fails.

Stage file format (CSV):
  name,mode,policy,duration,max_network_deny,max_audit_violations,max_audit_bypass

Example:
  canary-audit,audit,policies/default.fpl,300,0,50,0
  staging-enforce-10,enforce,policies/staging_enforce_10.fpl,300,15,200,10
  staging-enforce-50,enforce,policies/staging_enforce_50.fpl,300,25,200,10
  prod-enforce-100,enforce,policies/prod_enforce_100.fpl,300,40,200,10
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
      --proxy-port-base)
        PROXY_PORT_BASE="$2"
        shift 2
        ;;
      --metrics-port-base)
        METRICS_PORT_BASE="$2"
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

require_int "$PROXY_PORT_BASE" "--proxy-port-base"
require_int "$METRICS_PORT_BASE" "--metrics-port-base"

mkdir -p "$RUN_DIR"
summary_path="$RUN_DIR/summary-$(date -u +%Y%m%dT%H%M%SZ).txt"

echo "Network hardening progressive rollout" | tee -a "$summary_path"
echo "stage_file=$STAGE_FILE" | tee -a "$summary_path"
echo "run_dir=$RUN_DIR" | tee -a "$summary_path"
echo | tee -a "$summary_path"

stage_index=0
failed_count=0

while IFS=',' read -r raw_name raw_mode raw_policy raw_duration raw_max_deny raw_max_audit_violations raw_max_audit_bypass; do
  name="$(echo "${raw_name:-}" | xargs)"
  mode="$(echo "${raw_mode:-}" | xargs | tr '[:upper:]' '[:lower:]')"
  policy="$(echo "${raw_policy:-}" | xargs)"
  duration="$(echo "${raw_duration:-}" | xargs)"
  max_deny="$(echo "${raw_max_deny:-}" | xargs)"
  max_audit_violations="$(echo "${raw_max_audit_violations:-}" | xargs)"
  max_audit_bypass="$(echo "${raw_max_audit_bypass:-}" | xargs)"

  if [[ -z "$name" ]]; then
    continue
  fi
  if [[ "${name:0:1}" == "#" ]]; then
    continue
  fi
  if [[ "$name" == "name" && "$mode" == "mode" ]]; then
    continue
  fi

  if [[ "$mode" != "audit" && "$mode" != "enforce" ]]; then
    echo "invalid mode for stage '$name': $mode" | tee -a "$summary_path"
    failed_count=$((failed_count + 1))
    if [[ "$CONTINUE_ON_FAIL" != "true" ]]; then
      break
    fi
    continue
  fi

  if [[ -z "$policy" ]]; then
    echo "missing policy for stage '$name'" | tee -a "$summary_path"
    failed_count=$((failed_count + 1))
    if [[ "$CONTINUE_ON_FAIL" != "true" ]]; then
      break
    fi
    continue
  fi

  require_int "$duration" "duration($name)"
  require_int "$max_deny" "max_network_deny($name)"
  require_int "$max_audit_violations" "max_audit_violations($name)"
  require_int "$max_audit_bypass" "max_audit_bypass($name)"

  proxy_port=$((PROXY_PORT_BASE + stage_index * 10))
  metrics_port=$((METRICS_PORT_BASE + stage_index * 10))
  stage_slug="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//')"
  report_path="$RUN_DIR/${stage_slug}.json"

  cmd=(bash "$CORE_DIR/scripts/network_hardening_stage_gate.sh"
    --stage-name "$name"
    --mode "$mode"
    --policy "$policy"
    --duration "$duration"
    --proxy-port "$proxy_port"
    --metrics-port "$metrics_port"
    --max-network-deny "$max_deny"
    --max-audit-violations "$max_audit_violations"
    --max-audit-bypass "$max_audit_bypass"
    --run-dir "$RUN_DIR"
    --report "$report_path"
  )

  if [[ -n "$TRAFFIC_CMD" ]]; then
    cmd+=(--traffic-cmd "$TRAFFIC_CMD")
  fi
  if [[ -n "$ALLOW_PRIVATE_CIDRS" ]]; then
    cmd+=(--allow-private-cidrs "$ALLOW_PRIVATE_CIDRS")
  fi
  if [[ -n "$ALLOW_PRIVATE_HOSTS" ]]; then
    cmd+=(--allow-private-hosts "$ALLOW_PRIVATE_HOSTS")
  fi
  if [[ -n "$DAEMON_CMD" ]]; then
    cmd+=(--daemon-cmd "$DAEMON_CMD")
  fi
  if [[ -n "$EXTRA_SERVE_ARGS" ]]; then
    cmd+=(--extra-serve-args "$EXTRA_SERVE_ARGS")
  fi

  echo "running stage=$name mode=$mode policy=$policy duration=${duration}s" | tee -a "$summary_path"
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
