#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "$CORE_DIR/.." && pwd)"
cd "$CORE_DIR"

RUN_DIR="${FARAMESH_LANGGRAPH_REAL_DIR:-$CORE_DIR/.tmp/langgraph-real}"
BIN_PATH="${FARAMESH_LANGGRAPH_REAL_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_LANGGRAPH_REAL_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_LANGGRAPH_REAL_DATA:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_LANGGRAPH_REAL_POLICY:-$CORE_DIR/policies/langgraph_single_agent.fpl}"
DAEMON_LOG="${FARAMESH_LANGGRAPH_REAL_DAEMON_LOG:-$RUN_DIR/daemon.log}"
VAULT_LOG="${FARAMESH_LANGGRAPH_REAL_VAULT_LOG:-$RUN_DIR/vault.log}"
MANIFEST_PATH="${FARAMESH_LANGGRAPH_REAL_MANIFEST:-$RUN_DIR/integrity.json}"
BUILDINFO_PATH="${FARAMESH_LANGGRAPH_REAL_BUILDINFO:-$RUN_DIR/buildinfo.json}"
SPIFFE_SOCKET_PATH="${FARAMESH_LANGGRAPH_REAL_SPIFFE_SOCKET:-$RUN_DIR/spiffe.sock}"
AGENT_OUTPUT_PATH="${FARAMESH_LANGGRAPH_REAL_AGENT_OUTPUT:-$RUN_DIR/agent_output.log}"

AGENT_ID="${FARAMESH_LANGGRAPH_REAL_AGENT_ID:-langgraph-single}"
DPR_HMAC_KEY="${FARAMESH_LANGGRAPH_REAL_DPR_HMAC:-langgraph-real-replay-hmac}"
IDP_PROVIDER="${FARAMESH_LANGGRAPH_REAL_IDP_PROVIDER:-default}"
VAULT_ADDR="${FARAMESH_LANGGRAPH_REAL_VAULT_ADDR:-http://127.0.0.1:18210}"
VAULT_TOKEN="${FARAMESH_LANGGRAPH_REAL_VAULT_TOKEN:-root}"
SECRET_SENTINEL="${FARAMESH_LANGGRAPH_REAL_SECRET_VALUE:-vault-real-credential}"

cleanup() {
  set +e
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${VAULT_PID:-}" ]]; then
    kill "$VAULT_PID" >/dev/null 2>&1 || true
    wait "$VAULT_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

wait_for_daemon() {
  local attempts=100
  local delay_seconds=0.1

  for _ in $(seq 1 "$attempts"); do
    if "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
      echo "daemon exited before ready"
      cat "$DAEMON_LOG"
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "daemon readiness timeout"
  cat "$DAEMON_LOG"
  return 1
}

wait_for_vault() {
  local attempts=100
  local delay_seconds=0.1

  for _ in $(seq 1 "$attempts"); do
    if VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" vault status >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$VAULT_PID" >/dev/null 2>&1; then
      echo "vault exited before ready"
      cat "$VAULT_LOG"
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "vault readiness timeout"
  cat "$VAULT_LOG"
  return 1
}

resolve_python() {
  if [[ -n "${FARAMESH_LANGGRAPH_REAL_PYTHON:-}" ]]; then
    if [[ ! -x "$FARAMESH_LANGGRAPH_REAL_PYTHON" ]]; then
      echo "FARAMESH_LANGGRAPH_REAL_PYTHON is not executable: $FARAMESH_LANGGRAPH_REAL_PYTHON" >&2
      return 1
    fi
    echo "$FARAMESH_LANGGRAPH_REAL_PYTHON"
    return 0
  fi

  local venv_dir="$RUN_DIR/.venv"
  if [[ ! -x "$venv_dir/bin/python" ]]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet --upgrade pip
  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet "langgraph>=1.1.1,<1.2.0" -e "$CORE_DIR/sdk/python"
  echo "$venv_dir/bin/python"
}

if ! command -v vault >/dev/null 2>&1; then
  echo "vault CLI is required. Install with: brew install hashicorp/tap/vault" >&2
  exit 1
fi

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$RUN_DIR/home"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$VAULT_LOG" "$AGENT_OUTPUT_PATH"

PYTHON_BIN="$(resolve_python)"

VAULT_DEV_LISTEN="${VAULT_ADDR#http://}"
if [[ "$VAULT_ADDR" == https://* ]]; then
  echo "HTTPS VAULT_ADDR is not supported by this dev harness" >&2
  exit 1
fi

HOME="$RUN_DIR/home" vault server -dev -dev-no-store-token -dev-root-token-id "$VAULT_TOKEN" -dev-listen-address "$VAULT_DEV_LISTEN" >"$VAULT_LOG" 2>&1 &
VAULT_PID=$!
wait_for_vault

export VAULT_ADDR VAULT_TOKEN
vault kv put secret/faramesh/vault/probe value="$SECRET_SENTINEL" >/dev/null
vault kv put secret/faramesh/vault/probe/_execute_tool_sync value="$SECRET_SENTINEL" >/dev/null
vault kv put secret/faramesh/vault/probe/_execute_tool_async value="$SECRET_SENTINEL" >/dev/null
vault kv put secret/faramesh/vault/probe/_run_one value="$SECRET_SENTINEL" >/dev/null
vault kv put secret/faramesh/vault/probe/_arun_one value="$SECRET_SENTINEL" >/dev/null

go build -o "$BIN_PATH" ./cmd/faramesh

"$BIN_PATH" verify manifest-generate --base-dir "$CORE_DIR" --output "$MANIFEST_PATH" "$POLICY_PATH"
"$BIN_PATH" verify buildinfo --emit > "$BUILDINFO_PATH"

FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --dpr-hmac-key "$DPR_HMAC_KEY" \
  --strict-preflight \
  --idp-provider "$IDP_PROVIDER" \
  --vault-addr "$VAULT_ADDR" \
  --vault-token "$VAULT_TOKEN" \
  --vault-mount secret \
  --spiffe-socket "$SPIFFE_SOCKET_PATH" \
  --integrity-manifest "$MANIFEST_PATH" \
  --integrity-base-dir "$CORE_DIR" \
  --buildinfo-expected "$BUILDINFO_PATH" \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
wait_for_daemon

"$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity verify --spiffe "spiffe://example.org/agent/$AGENT_ID" >/dev/null

FARAMESH_SOCKET="$SOCKET_PATH" \
FARAMESH_AGENT_ID="$AGENT_ID" \
FARAMESH_BIN="$BIN_PATH" \
"$BIN_PATH" --daemon-socket "$SOCKET_PATH" run -- "$PYTHON_BIN" "$CORE_DIR/tests/langgraph_single_agent_dropin.py" >"$AGENT_OUTPUT_PATH" 2>&1

python3 - "$AGENT_OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
steps = {}
defer_statuses = {}
langgraph_patched_methods = []
langgraph_active_methods_after = []
langgraph_patch_verified = False
langgraph_patch_error = ""

with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue

        event = payload.get("event")
        if event == "startup":
            langgraph_patched_methods = payload.get("langgraph_patched_methods", [])
            langgraph_active_methods_after = payload.get("langgraph_active_methods_after", [])
            langgraph_patch_verified = bool(payload.get("langgraph_patch_verified", False))
            langgraph_patch_error = payload.get("langgraph_patch_error", "")
        elif event == "step":
            steps[payload.get("step")] = payload.get("status")
        elif event == "defer_status":
            defer_statuses[payload.get("step")] = payload.get("status")

required_steps = {
    "permit_http": "executed",
    "permit_vault": "executed",
    "deny_shell": "denied",
    "defer_approve": "deferred",
    "defer_deny": "deferred",
}

if langgraph_patch_error:
    raise SystemExit(f"langgraph interception install failed: {langgraph_patch_error}")
if not langgraph_patch_verified:
    raise SystemExit(
        "langgraph interception not active after install; "
        f"patched={langgraph_patched_methods} active={langgraph_active_methods_after}"
    )
if not any(m in ("_execute_tool_sync", "_execute_tool_async", "_run_one", "_arun_one") for m in langgraph_active_methods_after):
    raise SystemExit(f"unexpected active langgraph methods: {langgraph_active_methods_after}")

for step, expected in required_steps.items():
    actual = steps.get(step)
    if actual != expected:
        raise SystemExit(f"step {step} expected {expected} got {actual}")

if defer_statuses.get("defer_approve") != "approved":
    raise SystemExit(f"defer_approve token did not resolve to approved: {defer_statuses}")
if defer_statuses.get("defer_deny") != "denied":
    raise SystemExit(f"defer_deny token did not resolve to denied: {defer_statuses}")
PY

python3 - "$DATA_DIR/faramesh.db" "$AGENT_ID" <<'PY'
import sqlite3
import sys
import time

db_path = sys.argv[1]
agent_id = sys.argv[2]
con = sqlite3.connect(db_path)
cur = con.cursor()

def read_counts():
  cur.execute(
    "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
    (agent_id, "http/get%", "PERMIT"),
  )
  http_permit = cur.fetchone()[0]

  cur.execute(
    "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ? and credential_brokered = 1 and credential_source = ?",
    (agent_id, "vault/probe%", "PERMIT", "vault"),
  )
  vault_permit = cur.fetchone()[0]

  cur.execute(
    "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
    (agent_id, "shell/run%", "DENY"),
  )
  deny_shell_count = cur.fetchone()[0]

  cur.execute(
    "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
    (agent_id, "payment/refund%", "DEFER"),
  )
  defer_count = cur.fetchone()[0]

  return http_permit, vault_permit, deny_shell_count, defer_count


deadline = time.time() + 5.0
http_permit = 0
vault_permit = 0
deny_shell_count = 0
defer_count = 0

while True:
  http_permit, vault_permit, deny_shell_count, defer_count = read_counts()
  if http_permit >= 1 and vault_permit >= 1 and deny_shell_count >= 1 and defer_count >= 2:
    break
  if time.time() >= deadline:
    break
  time.sleep(0.1)

con.close()

if http_permit < 1:
    raise SystemExit("missing PERMIT DPR record for http/get")
if vault_permit < 1:
    raise SystemExit("missing vault-brokered PERMIT DPR record for vault/probe")
if deny_shell_count < 1:
    raise SystemExit("missing DENY DPR record for shell/run adversarial scenario")
if defer_count < 2:
    raise SystemExit("missing DEFER DPR records for payment/refund approve/deny scenarios")
PY

if rg -a -n --fixed-strings "$SECRET_SENTINEL" "$AGENT_OUTPUT_PATH" "$DAEMON_LOG" "$DATA_DIR" >/dev/null; then
  echo "secret sentinel leaked into Faramesh artifacts" >&2
  exit 1
fi

"$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
"$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --max-divergence 0 --strict-reason-parity --dpr-hmac-key "$DPR_HMAC_KEY"

echo "langgraph real-stack governance passed"
