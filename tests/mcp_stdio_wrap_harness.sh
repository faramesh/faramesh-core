#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${FARAMESH_MCP_STDIO_DIR:-$ROOT_DIR/.tmp/mcp-stdio-wrap}"
BIN_PATH="${FARAMESH_MCP_STDIO_BIN:-$RUN_DIR/faramesh}"
POLICY_PATH="${FARAMESH_MCP_STDIO_POLICY:-$RUN_DIR/policy.yaml}"
DATA_DIR="${FARAMESH_MCP_STDIO_DATA:-$RUN_DIR/data}"
DPR_HMAC_KEY="${FARAMESH_MCP_STDIO_REPLAY_HMAC:-mcp-stdio-wrap-replay-hmac}"

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$POLICY_PATH"

cat >"$POLICY_PATH" <<'YAML'
faramesh-version: "1.0"
agent-id: "mcp-stdio-wrap"
default_effect: deny
rules:
  - id: permit-safe-tool
    match:
      tool: "safe/tool"
      when: "true"
    effect: permit
    reason: allow safe tool
  - id: deny-danger-tool
    match:
      tool: "danger/*"
      when: "true"
    effect: deny
    reason: block dangerous tool
  - id: defer-review-tool
    match:
      tool: "review/*"
      when: "true"
    effect: defer
    reason: require approval for review tool
YAML

go build -o "$BIN_PATH" ./cmd/faramesh

export FARAMESH_MCP_STDIO_REPLAY_HMAC="$DPR_HMAC_KEY"

python3 - "$BIN_PATH" "$POLICY_PATH" "$ROOT_DIR" "$DATA_DIR" <<'PY'
import json
import os
import sqlite3
import subprocess
import sys
import time
import hashlib

bin_path, policy_path, root_dir, data_dir = sys.argv[1:]
dpr_hmac_key = os.environ.get("FARAMESH_MCP_STDIO_REPLAY_HMAC", "").strip()
if not dpr_hmac_key:
    raise SystemExit("FARAMESH_MCP_STDIO_REPLAY_HMAC must be set for replayable defer envelopes")

def run_wrap(args, writes, expect_notify=False):
    proc = subprocess.Popen(
        [
            bin_path,
            "mcp",
            "wrap",
            "--policy",
            policy_path,
            "--agent-id",
            "mcp-stdio-wrap",
            "--data-dir",
            data_dir,
            "--dpr-hmac-key",
            dpr_hmac_key,
            "--",
            *args,
        ],
        cwd=root_dir,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    lines = []
    if expect_notify:
        proc.stdin.write(writes[0] + "\n")
        proc.stdin.flush()
        for _ in range(4):
            raw = proc.stdout.readline()
            if not raw:
                break
            raw = raw.strip()
            if raw:
                lines.append(json.loads(raw))
            methods = {line.get("method") for line in lines if isinstance(line, dict)}
            have_notification = "notifications/progress" in methods
            have_response = any("result" in line and line.get("id") == 42 for line in lines if isinstance(line, dict))
            if have_notification and have_response:
                break
        proc.stdin.close()
    else:
        for line in writes:
            proc.stdin.write(line + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        for raw in proc.stdout:
            raw = raw.strip()
            if raw:
                lines.append(json.loads(raw))
    stderr = proc.stderr.read()
    code = proc.wait(timeout=10)
    if code != 0:
        raise SystemExit(f"mcp wrap failed exit={code} stderr={stderr}")
    if expect_notify and len(lines) < 2:
        raise SystemExit(f"expected notification + response, got {lines}")
    return lines

def stable_mcp_tool_call_id(agent_id, session_id, request_id, tool_name):
    raw_id = json.dumps(request_id, separators=(",", ":"))
    seed = f"{agent_id.strip()}|{session_id.strip()}|{tool_name.strip()}|{raw_id}"
    return "mcp-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

def deterministic_defer_token(call_id, tool_id):
    return hashlib.sha256(f"{call_id}{tool_id}".encode("utf-8")).hexdigest()[:8]

echo_lines = run_wrap(
    ["go", "run", "./internal/adapter/mcp/testdata/stdio_echo"],
    [
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"danger/x","arguments":{}}}',
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"review/pending","arguments":{"ticket":"T-42"}}}',
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"review/pending","arguments":{"ticket":"T-43"}}}',
        '{"jsonrpc":"2.0","id":5,"method":"ping","params":{}}',
    ],
)

if len(echo_lines) != 5:
    raise SystemExit(f"expected 5 stdio responses, got {echo_lines}")
if echo_lines[0].get("result", {}).get("echo") is not True:
    raise SystemExit(f"permit path did not echo true: {echo_lines[0]}")
deny_error = echo_lines[1].get("error") or {}
if deny_error.get("code") != -32003:
    raise SystemExit(f"deny path did not return MCP deny error: {echo_lines[1]}")
first_defer = echo_lines[2].get("result") or {}
second_defer = echo_lines[3].get("result") or {}
if first_defer.get("status") != "pending_approval":
    raise SystemExit(f"first defer path did not return pending approval response: {echo_lines[2]}")
if second_defer.get("status") != "pending_approval":
    raise SystemExit(f"second defer path did not return pending approval response: {echo_lines[3]}")
first_token = str(first_defer.get("defer_token", "")).strip()
second_token = str(second_defer.get("defer_token", "")).strip()
if not first_token:
    raise SystemExit(f"first defer path is missing a defer token: {echo_lines[2]}")
if not second_token:
    raise SystemExit(f"second defer path is missing a defer token: {echo_lines[3]}")
if first_token == second_token:
    raise SystemExit("expected distinct defer tokens for independent stdio wrap defer flows")
if echo_lines[4].get("result", {}).get("echo") is not True:
    raise SystemExit(f"non-tool passthrough did not forward upstream: {echo_lines[4]}")

control_token = deterministic_defer_token(
    stable_mcp_tool_call_id("mcp-stdio-wrap", "mcp-stdio-wrap-mcp", 11, "review/pending"),
    "review/pending",
)
control_lines = run_wrap(
    ["go", "run", "./internal/adapter/mcp/testdata/stdio_echo"],
    [
        '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"review/pending","arguments":{"ticket":"T-99"}}}',
        json.dumps({"jsonrpc": "2.0", "id": 12, "method": "faramesh/defer/status", "params": {"defer_token": control_token}}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "faramesh/defer/resolve",
                "params": {
                    "defer_token": control_token,
                    "approved": True,
                    "approver_id": "approver-42",
                    "reason": "approved in stdio wrap harness",
                },
            }
        ),
        json.dumps({"jsonrpc": "2.0", "id": 14, "method": "faramesh/defer/status", "params": {"defer_token": control_token}}),
        '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"review/pending","arguments":{"ticket":"T-99"}}}',
    ],
)
if len(control_lines) != 5:
    raise SystemExit(f"expected 5 control-flow responses, got {control_lines}")
control_defer = control_lines[0].get("result") or {}
returned_control_token = str(control_defer.get("defer_token", "")).strip()
if control_defer.get("status") != "pending_approval" or returned_control_token != control_token:
    raise SystemExit(f"control defer flow did not return pending approval with token: {control_lines}")

status_pending = control_lines[1]
pending_result = status_pending.get("result") or {}
if pending_result.get("status") != "pending":
    raise SystemExit(f"expected pending defer status, got {status_pending}")

resolve_result = control_lines[2]
resolved_result = resolve_result.get("result") or {}
if not resolved_result.get("ok"):
    raise SystemExit(f"expected successful defer resolution, got {resolve_result}")
if resolved_result.get("status") != "approved":
    raise SystemExit(f"expected approved defer resolution, got {resolve_result}")

status_approved = control_lines[3]
approved_result = status_approved.get("result") or {}
if approved_result.get("status") != "approved":
    raise SystemExit(f"expected approved defer status after resolution, got {status_approved}")

resume_line = control_lines[4]
resume_result = resume_line.get("result") or {}
if resume_result.get("echo") is not True:
    raise SystemExit(f"expected upstream tools/call resume after approval, got {resume_line}")

notify_lines = run_wrap(
    ["go", "run", "./internal/adapter/mcp/testdata/stdio_notify"],
    ['{"jsonrpc":"2.0","id":42,"method":"ping","params":{}}'],
    expect_notify=True,
)
notification = next((line for line in notify_lines if line.get("method") == "notifications/progress"), None)
response = next((line for line in notify_lines if line.get("id") == 42), None)
if notification is None:
    raise SystemExit(f"expected unsolicited notification, got {notify_lines}")
if (response or {}).get("result", {}).get("echo") is not True:
    raise SystemExit(f"expected response after notification flow, got {notify_lines}")

con = sqlite3.connect(f"{data_dir}/faramesh.db")
cur = con.cursor()

def read_counts():
    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id = ? and effect = ?",
        ("mcp-stdio-wrap", "safe/tool", "PERMIT"),
    )
    permit_count = cur.fetchone()[0]
    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id = ? and effect = ?",
        ("mcp-stdio-wrap", "danger/x", "DENY"),
    )
    deny_count = cur.fetchone()[0]
    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id = ? and effect = ?",
        ("mcp-stdio-wrap", "review/pending", "DEFER"),
    )
    defer_count = cur.fetchone()[0]
    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id = ? and effect = ?",
        ("mcp-stdio-wrap", "review/pending", "PERMIT"),
    )
    review_permit_count = cur.fetchone()[0]
    return permit_count, deny_count, defer_count, review_permit_count

deadline = time.time() + 5.0
permit_count = 0
deny_count = 0
defer_count = 0
review_permit_count = 0
while True:
    permit_count, deny_count, defer_count, review_permit_count = read_counts()
    if permit_count >= 1 and deny_count >= 1 and defer_count >= 3 and review_permit_count >= 1:
        break
    if time.time() >= deadline:
        break
    time.sleep(0.1)
con.close()

if permit_count < 1:
    raise SystemExit(f"missing PERMIT DPR coverage for safe/tool: {permit_count}")
if deny_count < 1:
    raise SystemExit(f"missing DENY DPR coverage for danger/x: {deny_count}")
if defer_count < 3:
    raise SystemExit(f"missing DEFER DPR coverage for review/pending: {defer_count}")
if review_permit_count < 1:
    raise SystemExit(f"missing PERMIT DPR coverage for resumed review/pending: {review_permit_count}")

print("mcp stdio wrap harness passed")
PY

"$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
"$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --max-divergence 0 --strict-reason-parity --dpr-hmac-key "$DPR_HMAC_KEY"
