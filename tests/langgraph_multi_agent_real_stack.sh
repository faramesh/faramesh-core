#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CORE_DIR"

RUN_DIR="${FARAMESH_LANGGRAPH_MULTI_DIR:-$CORE_DIR/.tmp/langgraph-multi-agent}"
BIN_PATH="${FARAMESH_LANGGRAPH_MULTI_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_LANGGRAPH_MULTI_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_LANGGRAPH_MULTI_DATA:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_LANGGRAPH_MULTI_POLICY:-$RUN_DIR/langgraph_multi_agent.yaml}"
DAEMON_LOG="${FARAMESH_LANGGRAPH_MULTI_DAEMON_LOG:-$RUN_DIR/daemon.log}"
AGENT_OUTPUT_PATH="${FARAMESH_LANGGRAPH_MULTI_AGENT_OUTPUT:-$RUN_DIR/agent_output.log}"
HMAC_KEY="${FARAMESH_LANGGRAPH_MULTI_HMAC_KEY:-approval-secret}"

AGENT_ID="${FARAMESH_LANGGRAPH_MULTI_AGENT_ID:-orch-1}"

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
  if [[ -n "${FARAMESH_LANGGRAPH_MULTI_PYTHON:-}" ]]; then
    if [[ ! -x "$FARAMESH_LANGGRAPH_MULTI_PYTHON" ]]; then
      echo "FARAMESH_LANGGRAPH_MULTI_PYTHON is not executable: $FARAMESH_LANGGRAPH_MULTI_PYTHON" >&2
      return 1
    fi
    echo "$FARAMESH_LANGGRAPH_MULTI_PYTHON"
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

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$AGENT_OUTPUT_PATH"

cat >"$POLICY_PATH" <<'EOF'
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
orchestrator_manifest:
  agent_id: "orch-1"
  undeclared_invocation_policy: deny
  permitted_invocations:
    - agent_id: "worker-a"
      max_invocations_per_session: 1
    - agent_id: "worker-b"
      max_invocations_per_session: 10
      requires_prior_approval: true
delegation_policies:
  - target_agent: "worker-a"
    scope: "safe/*"
    ttl: "1h"
    ceiling: "inherited"
  - target_agent: "worker-b"
    scope: "safe/*"
    ttl: "1h"
    ceiling: "approval"
rules:
  - id: allow-langgraph-invoke-agent
    match:
      tool: "multiagent/invoke_agent/*"
      when: "true"
    effect: permit
    reason: "langgraph multi-agent delegation is permitted when manifest and delegate policy allow it"
EOF

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
FARAMESH_BIN="$BIN_PATH" \
FARAMESH_DEFER_MODE="${FARAMESH_DEFER_MODE:-raise}" \
"$BIN_PATH" --daemon-socket "$SOCKET_PATH" run -- "$PYTHON_BIN" "$CORE_DIR/tests/langgraph_multi_agent_dropin.py" >"$AGENT_OUTPUT_PATH" 2>&1

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
    "permit_worker_a": "executed",
    "deny_missing_ttl": "denied",
    "deny_unknown_worker": "denied",
    "defer_worker_b_approve": "deferred",
    "defer_worker_b_deny": "deferred",
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

if defer_statuses.get("defer_worker_b_approve") != "approved":
    raise SystemExit(f"defer_worker_b_approve token did not resolve to approved: {defer_statuses}")
if defer_statuses.get("defer_worker_b_deny") != "denied":
    raise SystemExit(f"defer_worker_b_deny token did not resolve to denied: {defer_statuses}")
PY

python3 - "$SOCKET_PATH" "$AGENT_ID" <<'PY'
import json
import socket
import sys
import time

socket_path = sys.argv[1]
agent_id = sys.argv[2]
tool_id = "multiagent/invoke_agent/_execute_tool_sync"


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


resume_args = {
    "input": {
        "target_agent_id": "worker-b",
        "delegation_scope": "safe/read",
        "delegation_ttl": "30m",
    }
}
seed = send(
    {
        "type": "govern",
        "call_id": "route-approval-seed",
        "agent_id": agent_id,
        "session_id": "route-approval-session",
        "tool_id": tool_id,
        "args": resume_args,
    }
)
if str(seed.get("effect")) != "DEFER":
    raise SystemExit(f"expected DEFER for routing approval seed call, got {seed}")
token = str(seed.get("defer_token", "")).strip()
if not token:
    raise SystemExit(f"routing approval seed call missing defer token: {seed}")

approve = send(
    {
        "type": "approve_defer",
        "defer_token": token,
        "approved": True,
        "approver_id": "approver-42",
        "reason": "approved in LangGraph harness",
    }
)
if not approve.get("ok"):
    raise SystemExit(f"failed to approve routing defer token: {approve}")
poll(token, "approved")

resumed = send(
    {
        "type": "govern",
        "call_id": "route-approval-seed-resume",
        "agent_id": agent_id,
        "session_id": "route-approval-session",
        "tool_id": tool_id,
        "args": resume_args,
    }
)
if str(resumed.get("effect")) != "PERMIT":
    raise SystemExit(f"expected resumed routing DEFER call to PERMIT after approval, got {resumed}")

limit_args = {
    "input": {
        "target_agent_id": "worker-a",
        "delegation_scope": "safe/read",
        "delegation_ttl": "30m",
    }
}
first = send(
    {
        "type": "govern",
        "call_id": "route-limit-1",
        "agent_id": agent_id,
        "session_id": "route-limit-session",
        "tool_id": tool_id,
        "args": limit_args,
    }
)
if str(first.get("effect")) != "PERMIT":
    raise SystemExit(f"expected first worker-a call to permit, got {first}")

second = send(
    {
        "type": "govern",
        "call_id": "route-limit-2",
        "agent_id": agent_id,
        "session_id": "route-limit-session",
        "tool_id": tool_id,
        "args": limit_args,
    }
)
if str(second.get("effect")) != "DENY":
    raise SystemExit(f"expected second worker-a call in same session to deny, got {second}")
print("langgraph multi-agent resume and invocation-limit checks passed")
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
        (agent_id, "multiagent/invoke_agent%", "PERMIT"),
    )
    permit_count = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "multiagent/invoke_agent%", "DENY"),
    )
    deny_count = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "multiagent/invoke_agent%", "DEFER"),
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
        (agent_id, "route-approval-session", "multiagent/invoke_agent%"),
    )
    resumed_permit_with_envelope = cur.fetchone()[0]
    if permit_count >= 1 and deny_count >= 2 and defer_count >= 3 and resumed_permit_with_envelope >= 1:
        break
    if time.time() >= deadline:
        break
    time.sleep(0.1)

con.close()

if permit_count < 1:
    raise SystemExit(f"missing PERMIT DPR coverage for multiagent/invoke_agent: {permit_count}")
if deny_count < 2:
    raise SystemExit(f"missing DENY DPR coverage for multiagent/invoke_agent: {deny_count}")
if defer_count < 3:
    raise SystemExit(f"missing full DEFER DPR coverage for multiagent/invoke_agent: {defer_count}")
if resumed_permit_with_envelope < 1:
    raise SystemExit(
        "missing resumed PERMIT DPR row with approval_envelope for langgraph route-approval session"
    )
PY

"$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
"$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --dpr-hmac-key "$HMAC_KEY" --max-divergence 0 --strict-reason-parity

echo "langgraph multi-agent governance passed"
