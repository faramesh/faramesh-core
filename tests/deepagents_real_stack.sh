#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CORE_DIR"

RUN_DIR="${FARAMESH_DEEPAGENTS_REAL_DIR:-$CORE_DIR/.tmp/deepagents-real}"
BIN_PATH="${FARAMESH_DEEPAGENTS_REAL_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_DEEPAGENTS_REAL_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_DEEPAGENTS_REAL_DATA:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_DEEPAGENTS_REAL_POLICY:-$CORE_DIR/sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl}"
DAEMON_LOG="${FARAMESH_DEEPAGENTS_REAL_DAEMON_LOG:-$RUN_DIR/daemon.log}"
AGENT_OUTPUT_PATH="${FARAMESH_DEEPAGENTS_REAL_AGENT_OUTPUT:-$RUN_DIR/agent_output.log}"
HMAC_KEY="${FARAMESH_DEEPAGENTS_REAL_HMAC_KEY:-approval-secret}"

AGENT_ID="${FARAMESH_DEEPAGENTS_REAL_AGENT_ID:-deepagents-openrouter-qwen-prod}"

cleanup() {
  set +e
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
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
      sed -n '1,200p' "$DAEMON_LOG"
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "daemon readiness timeout"
  sed -n '1,200p' "$DAEMON_LOG"
  return 1
}

resolve_python() {
  if [[ -n "${FARAMESH_DEEPAGENTS_REAL_PYTHON:-}" ]]; then
    if [[ ! -x "$FARAMESH_DEEPAGENTS_REAL_PYTHON" ]]; then
      echo "FARAMESH_DEEPAGENTS_REAL_PYTHON is not executable: $FARAMESH_DEEPAGENTS_REAL_PYTHON" >&2
      return 1
    fi
    echo "$FARAMESH_DEEPAGENTS_REAL_PYTHON"
    return 0
  fi

  local venv_dir="$RUN_DIR/.venv"
  if [[ ! -x "$venv_dir/bin/python" ]]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet --upgrade pip
  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet deepagents -e "$CORE_DIR/sdk/python"
  echo "$venv_dir/bin/python"
}

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$AGENT_OUTPUT_PATH"

PYTHON_BIN="$(resolve_python)"

go build -o "$BIN_PATH" ./cmd/faramesh

"$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --dpr-hmac-key "$HMAC_KEY" \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
wait_for_daemon

FARAMESH_SOCKET="$SOCKET_PATH" \
FARAMESH_AGENT_ID="$AGENT_ID" \
FARAMESH_POLICY_PATH="$POLICY_PATH" \
FARAMESH_BIN="$BIN_PATH" \
FARAMESH_DEFER_MODE="${FARAMESH_DEFER_MODE:-raise}" \
"$BIN_PATH" --daemon-socket "$SOCKET_PATH" run -- "$PYTHON_BIN" "$CORE_DIR/sdk/python/examples/deepagents_openrouter_qwen_production.py" >"$AGENT_OUTPUT_PATH" 2>&1

python3 - "$AGENT_OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
text = open(path, "r", encoding="utf-8").read()
decoder = json.JSONDecoder()
report = None
i = 0

while i < len(text):
    if text[i] != "{":
        i += 1
        continue
    try:
        obj, end = decoder.raw_decode(text[i:])
    except Exception:
        i += 1
        continue
    if isinstance(obj, dict):
        report = obj
    i += max(end, 1)

if report is None:
    raise SystemExit("failed to parse DeepAgents JSON report")

patched = report.get("patched", {})
patch_markers = report.get("patch_markers", {})
langchain_methods = patch_markers.get("langchain_basetool_methods", {})

if not patch_markers.get("deepagents_create_patched", False):
    raise SystemExit(f"DeepAgents create_deep_agent is not marked patched: {patch_markers}")
if patched.get("deepagents") not in (None, [], ["create_deep_agent"]):
    raise SystemExit(f"unexpected DeepAgents patch report: {patched}")
if not any(bool(v) for v in langchain_methods.values()):
    raise SystemExit(f"LangChain BaseTool patch markers missing: {langchain_methods}")

permit_probe = report.get("permit_probe", {})
if not str(permit_probe.get("result", "")).startswith("infra-status::"):
    raise SystemExit(f"permit probe did not execute infra_status: {permit_probe}")

deny_probe = report.get("deny_probe", {})
if not deny_probe.get("blocked", False):
    raise SystemExit(f"deny probe did not block bash_run: {deny_probe}")

defer_probe = report.get("defer_probe", {})
if not defer_probe.get("deferred", False):
    raise SystemExit(f"defer probe did not defer payments_refund: {defer_probe}")
if not str(defer_probe.get("defer_token", "")).strip():
    raise SystemExit(f"defer probe is missing defer token: {defer_probe}")

execute_permit = report.get("deepagents_execute_permit_probe", {})
if "infra_status" not in execute_permit.get("tool_calls", []):
    raise SystemExit(f"DeepAgents execute-layer permit probe missing infra_status: {execute_permit}")

execute_deny = report.get("deepagents_execute_deny_probe", {})
if not execute_deny.get("blocked", False):
    raise SystemExit(f"DeepAgents execute-layer deny probe did not block bash_run: {execute_deny}")

live_call = report.get("live_call", {})
live_status = live_call.get("status")
if live_status not in {"skipped", "ok"}:
    raise SystemExit(f"unexpected live_call status: {live_call}")
PY

python3 - "$SOCKET_PATH" "$AGENT_ID" <<'PY'
import json
import socket
import sys
import time

socket_path = sys.argv[1]
agent_id = sys.argv[2]
tool_id = "payments_refund/invoke"
call_id = "deepagents-refund-approval"
session_id = "deepagents-resume-session"
args = {"amount": 1200, "currency": "USD"}


def send(payload):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(5.0)
    conn.connect(socket_path)
    conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    conn.close()
    if not data:
        raise RuntimeError("empty response from daemon")
    return json.loads(data.decode("utf-8").strip())


def poll(token, expected):
    deadline = time.time() + 5.0
    while time.time() < deadline:
        resp = send({"type": "poll_defer", "agent_id": agent_id, "defer_token": token})
        status = str(resp.get("status", "")).lower()
        if status == expected:
            return
        time.sleep(0.1)
    raise RuntimeError(f"defer token {token} did not reach {expected}")


first = send(
    {
        "type": "govern",
        "call_id": call_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_id": tool_id,
        "args": args,
    }
)
if str(first.get("effect")) != "DEFER":
    raise SystemExit(f"expected DEFER for resume seed call, got {first}")
token = str(first.get("defer_token", "")).strip()
if not token:
    raise SystemExit(f"resume seed call missing defer token: {first}")

approve = send(
    {
        "type": "approve_defer",
        "defer_token": token,
        "approved": True,
        "approver_id": "approver-42",
        "reason": "approved in DeepAgents harness",
    }
)
if not approve.get("ok"):
    raise SystemExit(f"failed to approve defer token: {approve}")
poll(token, "approved")

resumed = send(
    {
        "type": "govern",
        "call_id": call_id + "-resume",
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_id": tool_id,
        "args": args,
    }
)
if str(resumed.get("effect")) != "PERMIT":
    raise SystemExit(f"expected resumed DEFER call to PERMIT after approval, got {resumed}")
print("deepagents resume approval checks passed")
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
        (agent_id, "infra_status%", "PERMIT"),
    )
    permit_count = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "bash_run%", "DENY"),
    )
    deny_count = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "payments_refund%", "DEFER"),
    )
    defer_count = cur.fetchone()[0]
    return permit_count, deny_count, defer_count


deadline = time.time() + 10.0
permit_count = 0
deny_count = 0
defer_count = 0
resumed_permit_with_envelope = 0

while True:
    permit_count, deny_count, defer_count = read_counts()
    cur.execute(
        """
        select count(*)
        from dpr_records
        where agent_id = ?
          and session_id = ?
          and tool_id like ?
          and effect = 'PERMIT'
          and approval_envelope is not null
          and trim(approval_envelope) <> ''
        """,
        (agent_id, "deepagents-resume-session", "payments_refund%"),
    )
    resumed_permit_with_envelope = cur.fetchone()[0]
    if permit_count >= 2 and deny_count >= 2 and defer_count >= 1 and resumed_permit_with_envelope >= 1:
        break
    if time.time() >= deadline:
        break
    time.sleep(0.1)

con.close()

if permit_count < 2:
    raise SystemExit(f"missing PERMIT DPR coverage for infra_status: {permit_count}")
if deny_count < 2:
    raise SystemExit(f"missing DENY DPR coverage for bash_run: {deny_count}")
if defer_count < 1:
    raise SystemExit(f"missing DEFER DPR coverage for payments_refund: {defer_count}")
if resumed_permit_with_envelope < 1:
    raise SystemExit(
        "missing resumed PERMIT DPR row with approval_envelope for deepagents resume session"
    )
PY

"$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
"$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --dpr-hmac-key "$HMAC_KEY" --max-divergence 0 --strict-reason-parity

echo "deepagents real-stack governance passed"
