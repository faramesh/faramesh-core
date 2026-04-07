#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "$CORE_DIR/.." && pwd)"

RUN_DIR="${FARAMESH_WIZARD_DIR:-$CORE_DIR/.tmp/faramesh-wizard}"
BIN_PATH="${FARAMESH_WIZARD_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_WIZARD_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_WIZARD_DATA:-$RUN_DIR/data}"
DAEMON_LOG="${FARAMESH_WIZARD_DAEMON_LOG:-$RUN_DIR/daemon.log}"
VAULT_LOG="${FARAMESH_WIZARD_VAULT_LOG:-$RUN_DIR/vault.log}"
MANIFEST_PATH="${FARAMESH_WIZARD_MANIFEST:-$RUN_DIR/integrity.json}"
BUILDINFO_PATH="${FARAMESH_WIZARD_BUILDINFO:-$RUN_DIR/buildinfo.json}"
SPIFFE_SOCKET_PATH="${FARAMESH_WIZARD_SPIFFE_SOCKET:-$RUN_DIR/spiffe.sock}"
ENV_FILE="${FARAMESH_WIZARD_ENV_FILE:-$RUN_DIR/env.sh}"
RUN_HELPER="${FARAMESH_WIZARD_RUN_HELPER:-$RUN_DIR/run-agent.sh}"

DAEMON_PID_FILE="$RUN_DIR/daemon.pid"
VAULT_PID_FILE="$RUN_DIR/vault.pid"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/faramesh_govern_wizard.sh [options]
  bash scripts/faramesh_govern_wizard.sh status
  bash scripts/faramesh_govern_wizard.sh stop

This wizard is framework-first and production-oriented:
1) choose framework and policy,
2) choose security profile/options,
3) start governed runtime,
4) run your agent command.

Options:
  --yes                                   Use defaults with no prompts
  --framework <name>                      langchain|langgraph|deepagents|mcp|custom
  --agent-cmd <cmd>                       Agent command to run under governance
  --policy <path>                         Policy file path (.fpl or .yaml)
  --agent-id <id>                         Agent ID override
  --idp <provider>                        IdP provider (default: default)
  --strict <yes|no>                       Enable strict startup gates (default: yes)
  --credential-profile <mode>             production|development|auto (default: production)
  --credential-backend <backend>          auto|local-vault|vault|aws|gcp|azure|1password|infisical|env
  --allow-env-credential-fallback <bool>  yes|no (default: development=yes, production=no)
  --with-vault <mode>                     auto|on|off (default: auto)
  --run-now <yes|no>                      Run agent command immediately (default: yes)
  -h, --help                              Show this help

Examples:
  bash scripts/faramesh_govern_wizard.sh
  bash scripts/faramesh_govern_wizard.sh --framework langgraph --agent-cmd "python my_agent.py"
  bash scripts/faramesh_govern_wizard.sh --framework mcp --agent-cmd "node mcp_server.js" --run-now no
  bash scripts/faramesh_govern_wizard.sh stop
EOF
}

stop_by_pid_file() {
  local pid_file="$1"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    sleep 0.2
  fi
  rm -f "$pid_file"
}

wait_for_daemon() {
  local attempts=120
  local delay_seconds=0.1

  for _ in $(seq 1 "$attempts"); do
    if "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status >/dev/null 2>&1; then
      return 0
    fi
    local daemon_pid=""
    daemon_pid="$(cat "$DAEMON_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$daemon_pid" ]] && ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
      echo "daemon failed to start" >&2
      tail -n 120 "$DAEMON_LOG" >&2 || true
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "daemon readiness timeout" >&2
  tail -n 120 "$DAEMON_LOG" >&2 || true
  return 1
}

wait_for_vault() {
  local addr="$1"
  local token="$2"
  local attempts=120
  local delay_seconds=0.1

  for _ in $(seq 1 "$attempts"); do
    if VAULT_ADDR="$addr" VAULT_TOKEN="$token" vault status >/dev/null 2>&1; then
      return 0
    fi
    local vault_pid=""
    vault_pid="$(cat "$VAULT_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$vault_pid" ]] && ! kill -0 "$vault_pid" >/dev/null 2>&1; then
      echo "vault failed to start" >&2
      tail -n 120 "$VAULT_LOG" >&2 || true
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "vault readiness timeout" >&2
  tail -n 120 "$VAULT_LOG" >&2 || true
  return 1
}

prompt_default() {
  local prompt="$1"
  local default_value="$2"
  local value=""
  read -r -p "$prompt [$default_value]: " value || true
  echo "${value:-$default_value}"
}

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

normalize_framework() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    langchain|langgraph|deepagents|mcp|custom)
      echo "$raw"
      ;;
    lc)
      echo "langchain"
      ;;
    lg)
      echo "langgraph"
      ;;
    da)
      echo "deepagents"
      ;;
    *)
      echo ""
      ;;
  esac
}

normalize_credential_profile() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    production|development|auto)
      echo "$raw"
      ;;
    prod)
      echo "production"
      ;;
    dev)
      echo "development"
      ;;
    *)
      echo ""
      ;;
  esac
}

normalize_credential_backend() {
  local raw
  raw="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    auto|local-vault|vault|aws|gcp|azure|1password|infisical|env)
      echo "$raw"
      ;;
    local)
      echo "local-vault"
      ;;
    *)
      echo ""
      ;;
  esac
}

framework_default_policy() {
  local framework="$1"
  case "$framework" in
    langchain)
      echo "$CORE_DIR/policies/langchain_single_agent.fpl"
      ;;
    langgraph)
      echo "$CORE_DIR/policies/langgraph_single_agent.fpl"
      ;;
    deepagents)
      if [[ -f "$CORE_DIR/sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl" ]]; then
        echo "$CORE_DIR/sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl"
      else
        echo "$CORE_DIR/policies/langgraph_single_agent.fpl"
      fi
      ;;
    mcp)
      echo "$CORE_DIR/examples/mcp-server.fpl"
      ;;
    custom)
      echo "$CORE_DIR/policies/default.fpl"
      ;;
    *)
      echo "$CORE_DIR/policies/default.fpl"
      ;;
  esac
}

framework_default_agent_cmd() {
  local framework="$1"
  case "$framework" in
    langchain)
      echo "python demo_interactive_ai_agent.py"
      ;;
    langgraph)
      echo "python faramesh-core/tests/langgraph_single_agent_dropin.py"
      ;;
    deepagents)
      echo "python faramesh-core/sdk/python/examples/deepagents_openrouter_qwen_production.py"
      ;;
    mcp)
      echo "node your-mcp-server.js"
      ;;
    custom)
      echo "python your_agent.py"
      ;;
    *)
      echo "python your_agent.py"
      ;;
  esac
}

resolve_policy_path() {
  local input="$1"
  if [[ "$input" == /* ]] && [[ -f "$input" ]]; then
    echo "$input"
    return 0
  fi
  if [[ -f "$PWD/$input" ]]; then
    echo "$PWD/$input"
    return 0
  fi
  if [[ -f "$CORE_DIR/$input" ]]; then
    echo "$CORE_DIR/$input"
    return 0
  fi
  if [[ -f "$WORKSPACE_DIR/$input" ]]; then
    echo "$WORKSPACE_DIR/$input"
    return 0
  fi
  echo "$input"
}

if [[ "${1:-}" == "stop" ]]; then
  stop_by_pid_file "$DAEMON_PID_FILE"
  stop_by_pid_file "$VAULT_PID_FILE"
  rm -f "$SOCKET_PATH"
  echo "wizard runtime stopped"
  exit 0
fi

if [[ "${1:-}" == "status" ]]; then
  if [[ -f "$DAEMON_PID_FILE" ]]; then
    daemon_pid="$(cat "$DAEMON_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" >/dev/null 2>&1; then
      echo "daemon: running (pid $daemon_pid)"
    else
      echo "daemon: not running"
    fi
  else
    echo "daemon: not running"
  fi

  if [[ -f "$VAULT_PID_FILE" ]]; then
    vault_pid="$(cat "$VAULT_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$vault_pid" ]] && kill -0 "$vault_pid" >/dev/null 2>&1; then
      echo "vault: running (pid $vault_pid)"
    else
      echo "vault: not running"
    fi
  else
    echo "vault: not running"
  fi

  echo "socket: $SOCKET_PATH"
  echo "run helper: $RUN_HELPER"
  exit 0
fi

ASSUME_YES=0
FRAMEWORK_INPUT="${FARAMESH_WIZARD_FRAMEWORK:-langchain}"
AGENT_CMD_INPUT="${FARAMESH_WIZARD_AGENT_CMD:-}"
POLICY_INPUT="${FARAMESH_WIZARD_POLICY:-}"
IDP_PROVIDER_INPUT="${FARAMESH_WIZARD_IDP_PROVIDER:-default}"
WITH_VAULT_INPUT="${FARAMESH_WIZARD_WITH_VAULT:-auto}"
RUN_NOW_INPUT="${FARAMESH_WIZARD_RUN_NOW:-}"
AGENT_ID_INPUT="${FARAMESH_WIZARD_AGENT_ID:-}"
STRICT_INPUT="${FARAMESH_WIZARD_STRICT:-yes}"
CREDENTIAL_PROFILE_INPUT="${FARAMESH_WIZARD_CREDENTIAL_PROFILE:-production}"
CREDENTIAL_BACKEND_INPUT="${FARAMESH_WIZARD_CREDENTIAL_BACKEND:-auto}"
ALLOW_ENV_FALLBACK_INPUT="${FARAMESH_WIZARD_ALLOW_ENV_CREDENTIAL_FALLBACK:-}"
SPIFFE_ID_INPUT="${FARAMESH_WIZARD_SPIFFE_ID:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)
      ASSUME_YES=1
      ;;
    --framework)
      FRAMEWORK_INPUT="${2:-}"
      shift
      ;;
    --agent-cmd)
      AGENT_CMD_INPUT="${2:-}"
      shift
      ;;
    --policy)
      POLICY_INPUT="${2:-}"
      shift
      ;;
    --idp)
      IDP_PROVIDER_INPUT="${2:-}"
      shift
      ;;
    --with-vault)
      WITH_VAULT_INPUT="${2:-}"
      shift
      ;;
    --run-now)
      RUN_NOW_INPUT="${2:-}"
      shift
      ;;
    --agent-id)
      AGENT_ID_INPUT="${2:-}"
      shift
      ;;
    --strict)
      STRICT_INPUT="${2:-}"
      shift
      ;;
    --credential-profile)
      CREDENTIAL_PROFILE_INPUT="${2:-}"
      shift
      ;;
    --credential-backend)
      CREDENTIAL_BACKEND_INPUT="${2:-}"
      shift
      ;;
    --allow-env-credential-fallback)
      ALLOW_ENV_FALLBACK_INPUT="${2:-}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if ! command -v go >/dev/null 2>&1; then
  echo "missing dependency: go" >&2
  exit 1
fi

FRAMEWORK_INPUT="$(normalize_framework "$FRAMEWORK_INPUT")"
if [[ -z "$FRAMEWORK_INPUT" ]]; then
  echo "invalid framework. expected: langchain|langgraph|deepagents|mcp|custom" >&2
  exit 1
fi

if [[ "$ASSUME_YES" -eq 0 ]]; then
  FRAMEWORK_INPUT="$(prompt_default "Framework (langchain|langgraph|deepagents|mcp|custom)" "$FRAMEWORK_INPUT")"
  FRAMEWORK_INPUT="$(normalize_framework "$FRAMEWORK_INPUT")"
  if [[ -z "$FRAMEWORK_INPUT" ]]; then
    echo "invalid framework selection" >&2
    exit 1
  fi
fi

if [[ -z "$POLICY_INPUT" ]]; then
  POLICY_INPUT="$(framework_default_policy "$FRAMEWORK_INPUT")"
fi

default_agent_cmd="$(framework_default_agent_cmd "$FRAMEWORK_INPUT")"

if [[ -z "$AGENT_CMD_INPUT" ]]; then
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    AGENT_CMD_INPUT="$default_agent_cmd"
  else
    AGENT_CMD_INPUT="$(prompt_default "Agent command" "$default_agent_cmd")"
  fi
fi

if [[ "$ASSUME_YES" -eq 0 ]]; then
  POLICY_INPUT="$(prompt_default "Policy path" "$POLICY_INPUT")"
  CREDENTIAL_PROFILE_INPUT="$(prompt_default "Credential profile (production|development|auto)" "$CREDENTIAL_PROFILE_INPUT")"
  STRICT_INPUT="$(prompt_default "Strict startup gates (yes|no)" "$STRICT_INPUT")"
  if [[ "$CREDENTIAL_BACKEND_INPUT" == "auto" ]]; then
    if [[ "$(normalize_credential_profile "$CREDENTIAL_PROFILE_INPUT")" == "development" ]]; then
      CREDENTIAL_BACKEND_INPUT="env"
    else
      CREDENTIAL_BACKEND_INPUT="local-vault"
    fi
  fi
  CREDENTIAL_BACKEND_INPUT="$(prompt_default "Credential backend (auto|local-vault|vault|aws|gcp|azure|1password|infisical|env)" "$CREDENTIAL_BACKEND_INPUT")"
  RUN_NOW_INPUT="$(prompt_default "Run command now (yes|no)" "${RUN_NOW_INPUT:-yes}")"
fi

CREDENTIAL_PROFILE_INPUT="$(normalize_credential_profile "$CREDENTIAL_PROFILE_INPUT")"
if [[ -z "$CREDENTIAL_PROFILE_INPUT" ]]; then
  echo "invalid credential profile. expected: production|development|auto" >&2
  exit 1
fi

CREDENTIAL_BACKEND_INPUT="$(normalize_credential_backend "$CREDENTIAL_BACKEND_INPUT")"
if [[ -z "$CREDENTIAL_BACKEND_INPUT" ]]; then
  echo "invalid credential backend. expected: auto|local-vault|vault|aws|gcp|azure|1password|infisical|env" >&2
  exit 1
fi

STRICT_INPUT="$(normalize_yes_no "$STRICT_INPUT")"
if [[ -z "$STRICT_INPUT" ]]; then
  echo "invalid --strict value. expected yes or no" >&2
  exit 1
fi

STRICT_BOOL="false"
if [[ "$STRICT_INPUT" == "yes" ]]; then
  STRICT_BOOL="true"
fi

if [[ -z "$RUN_NOW_INPUT" ]]; then
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    RUN_NOW_INPUT="yes"
  else
    RUN_NOW_INPUT="$(prompt_default "Run command now (yes|no)" "yes")"
  fi
fi
RUN_NOW_INPUT="$(normalize_yes_no "$RUN_NOW_INPUT")"
if [[ -z "$RUN_NOW_INPUT" ]]; then
  echo "invalid --run-now value" >&2
  exit 1
fi

if [[ -z "$ALLOW_ENV_FALLBACK_INPUT" ]]; then
  if [[ "$CREDENTIAL_PROFILE_INPUT" == "development" ]]; then
    ALLOW_ENV_FALLBACK_INPUT="yes"
  else
    ALLOW_ENV_FALLBACK_INPUT="no"
  fi
fi
ALLOW_ENV_FALLBACK_INPUT="$(normalize_yes_no "$ALLOW_ENV_FALLBACK_INPUT")"
if [[ -z "$ALLOW_ENV_FALLBACK_INPUT" ]]; then
  echo "invalid --allow-env-credential-fallback value. expected yes or no" >&2
  exit 1
fi

WITH_VAULT_INPUT="$(echo "$WITH_VAULT_INPUT" | tr '[:upper:]' '[:lower:]')"
if [[ "$WITH_VAULT_INPUT" != "auto" && "$WITH_VAULT_INPUT" != "on" && "$WITH_VAULT_INPUT" != "off" ]]; then
  echo "invalid --with-vault mode: $WITH_VAULT_INPUT" >&2
  exit 1
fi

if [[ "$CREDENTIAL_BACKEND_INPUT" == "local-vault" && "$WITH_VAULT_INPUT" == "auto" ]]; then
  WITH_VAULT_INPUT="on"
fi
if [[ "$CREDENTIAL_BACKEND_INPUT" == "vault" && "$WITH_VAULT_INPUT" == "auto" ]]; then
  WITH_VAULT_INPUT="off"
fi

POLICY_PATH="$(resolve_policy_path "$POLICY_INPUT")"
if [[ ! -f "$POLICY_PATH" ]]; then
  echo "policy file not found: $POLICY_PATH" >&2
  exit 1
fi

if [[ -z "$AGENT_ID_INPUT" ]]; then
  AGENT_ID_INPUT="$(echo "$AGENT_CMD_INPUT" | tr '[:space:]' '-' | tr -cd '[:alnum:]_-/.' | tr '/.' '-')"
fi
if [[ -z "$AGENT_ID_INPUT" ]]; then
  AGENT_ID_INPUT="agent"
fi

if [[ -z "$SPIFFE_ID_INPUT" ]]; then
  SPIFFE_ID_INPUT="spiffe://example.org/agent/$AGENT_ID_INPUT"
fi

mkdir -p "$RUN_DIR" "$DATA_DIR"
rm -f "$SOCKET_PATH"

stop_by_pid_file "$DAEMON_PID_FILE"
stop_by_pid_file "$VAULT_PID_FILE"

USE_VAULT=0
VAULT_ADDR="${FARAMESH_WIZARD_VAULT_ADDR:-http://127.0.0.1:18200}"
VAULT_TOKEN="${FARAMESH_WIZARD_VAULT_TOKEN:-root}"
SECRET_SENTINEL="${FARAMESH_WIZARD_SECRET_VALUE:-vault-real-credential}"

if [[ "$WITH_VAULT_INPUT" == "on" ]]; then
  if ! command -v vault >/dev/null 2>&1; then
    echo "vault requested but vault CLI is not installed" >&2
    exit 1
  fi
  if [[ "$VAULT_ADDR" == https://* ]]; then
    echo "wizard local vault mode only supports http:// addresses" >&2
    exit 1
  fi

  if ! VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" vault status >/dev/null 2>&1; then
    vault server -dev -dev-root-token-id "$VAULT_TOKEN" -dev-listen-address "${VAULT_ADDR#http://}" >"$VAULT_LOG" 2>&1 &
    echo "$!" >"$VAULT_PID_FILE"
    wait_for_vault "$VAULT_ADDR" "$VAULT_TOKEN"
  fi

  export VAULT_ADDR VAULT_TOKEN
  vault kv put secret/faramesh/vault/probe value="$SECRET_SENTINEL" >/dev/null
  vault kv put secret/faramesh/vault/probe/_execute_tool_sync value="$SECRET_SENTINEL" >/dev/null
  USE_VAULT=1
fi

(
  cd "$CORE_DIR"
  go build -o "$BIN_PATH" ./cmd/faramesh
  "$BIN_PATH" verify manifest-generate --base-dir "$CORE_DIR" --output "$MANIFEST_PATH" "$POLICY_PATH"
  "$BIN_PATH" verify buildinfo --emit >"$BUILDINFO_PATH"
)

onboard_interactive="false"
if [[ "$ASSUME_YES" -eq 0 && -t 0 && -t 1 ]]; then
  onboard_interactive="true"
fi

run_onboard_preflight() {
  local -a onboard_cmd
  onboard_cmd=(
    "$BIN_PATH" onboard
    --strict="$STRICT_BOOL"
    --interactive="$onboard_interactive"
    --policy "$POLICY_PATH"
    --idp-provider "$IDP_PROVIDER_INPUT"
    --spiffe-socket "$SPIFFE_SOCKET_PATH"
    --spiffe-id "$SPIFFE_ID_INPUT"
    --credential-profile "$CREDENTIAL_PROFILE_INPUT"
    --credential-backend "$CREDENTIAL_BACKEND_INPUT"
  )
  if [[ "$USE_VAULT" -eq 1 ]]; then
    onboard_cmd+=(--vault-addr "$VAULT_ADDR")
  fi

  if [[ "$ALLOW_ENV_FALLBACK_INPUT" == "yes" ]]; then
    FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK=true "${onboard_cmd[@]}"
  else
    FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK=false "${onboard_cmd[@]}"
  fi
}

run_onboard_preflight

serve_cmd=(
  "$BIN_PATH" serve
  --policy "$POLICY_PATH"
  --socket "$SOCKET_PATH"
  --data-dir "$DATA_DIR"
  --idp-provider "$IDP_PROVIDER_INPUT"
  --spiffe-socket "$SPIFFE_SOCKET_PATH"
  --spiffe-id "$SPIFFE_ID_INPUT"
  --integrity-manifest "$MANIFEST_PATH"
  --integrity-base-dir "$CORE_DIR"
  --buildinfo-expected "$BUILDINFO_PATH"
  --log-level warn
)

if [[ "$STRICT_INPUT" == "yes" ]]; then
  serve_cmd+=(--strict-preflight --skip-onboard-preflight)
fi

if [[ "$ALLOW_ENV_FALLBACK_INPUT" == "yes" ]]; then
  serve_cmd+=(--allow-env-credential-fallback)
fi

if [[ "$USE_VAULT" -eq 1 ]]; then
  serve_cmd+=(--vault-addr "$VAULT_ADDR" --vault-token "$VAULT_TOKEN" --vault-mount secret)
elif [[ "$CREDENTIAL_BACKEND_INPUT" == "vault" ]]; then
  if [[ -n "${VAULT_ADDR:-}" ]]; then
    serve_cmd+=(--vault-addr "$VAULT_ADDR")
  fi
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    serve_cmd+=(--vault-token "$VAULT_TOKEN")
  fi
elif [[ "$CREDENTIAL_BACKEND_INPUT" == "aws" && -n "${FARAMESH_CREDENTIAL_AWS_REGION:-}" ]]; then
  serve_cmd+=(--aws-secrets-region "$FARAMESH_CREDENTIAL_AWS_REGION")
elif [[ "$CREDENTIAL_BACKEND_INPUT" == "gcp" && -n "${FARAMESH_CREDENTIAL_GCP_PROJECT:-}" ]]; then
  serve_cmd+=(--gcp-secrets-project "$FARAMESH_CREDENTIAL_GCP_PROJECT")
elif [[ "$CREDENTIAL_BACKEND_INPUT" == "azure" && -n "${FARAMESH_CREDENTIAL_AZURE_VAULT_URL:-}" ]]; then
  serve_cmd+=(--azure-vault-url "$FARAMESH_CREDENTIAL_AZURE_VAULT_URL")
fi

FARAMESH_SPIFFE_ID="$SPIFFE_ID_INPUT" "${serve_cmd[@]}" >"$DAEMON_LOG" 2>&1 &
echo "$!" >"$DAEMON_PID_FILE"
wait_for_daemon

"$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity verify --spiffe "$SPIFFE_ID_INPUT" >/dev/null

cat >"$ENV_FILE" <<EOF
export FARAMESH_SOCKET="$SOCKET_PATH"
export FARAMESH_AGENT_ID="$AGENT_ID_INPUT"
export FARAMESH_POLICY_PATH="$POLICY_PATH"
export FARAMESH_BIN="$BIN_PATH"
export FARAMESH_WORKSPACE_DIR="$WORKSPACE_DIR"
export FARAMESH_WIZARD_FRAMEWORK="$FRAMEWORK_INPUT"
export FARAMESH_WIZARD_STRICT="$STRICT_INPUT"
export FARAMESH_WIZARD_CREDENTIAL_PROFILE="$CREDENTIAL_PROFILE_INPUT"
export FARAMESH_WIZARD_CREDENTIAL_BACKEND="$CREDENTIAL_BACKEND_INPUT"
EOF

cat >"$RUN_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$RUN_DIR/env.sh"
if [[ "${1:-}" == "--" ]]; then
  shift
fi
if [[ $# -eq 0 ]]; then
  echo "usage: $0 -- <command> [args...]" >&2
  exit 1
fi
(
  cd "$FARAMESH_WORKSPACE_DIR"
  FARAMESH_SOCKET="$FARAMESH_SOCKET" \
  FARAMESH_AGENT_ID="$FARAMESH_AGENT_ID" \
  "$FARAMESH_BIN" run --enforce full --policy "$FARAMESH_POLICY_PATH" -- "$@"
)
EOF
chmod +x "$RUN_HELPER"

if [[ "$RUN_NOW_INPUT" == "yes" ]]; then
  (
    cd "$WORKSPACE_DIR"
    FARAMESH_SOCKET="$SOCKET_PATH" \
    FARAMESH_AGENT_ID="$AGENT_ID_INPUT" \
    "$BIN_PATH" run --enforce full --policy "$POLICY_PATH" -- \
      bash -lc "$AGENT_CMD_INPUT"
  )
fi

echo "ready"
echo "framework: $FRAMEWORK_INPUT"
echo "strict: $STRICT_INPUT"
echo "credential_profile: $CREDENTIAL_PROFILE_INPUT"
echo "credential_backend: $CREDENTIAL_BACKEND_INPUT"
echo "socket: $SOCKET_PATH"
echo "policy: $POLICY_PATH"
echo "run another command: $RUN_HELPER -- <command> [args]"
echo "status: bash $CORE_DIR/scripts/faramesh_govern_wizard.sh status"
echo "stop: bash $CORE_DIR/scripts/faramesh_govern_wizard.sh stop"
echo "offboard project wiring: bash $CORE_DIR/scripts/faramesh_setup.sh offboard --path <agent-project>"
echo "uninstall + detach: bash $CORE_DIR/scripts/faramesh_setup.sh uninstall --path <agent-project> --yes"
