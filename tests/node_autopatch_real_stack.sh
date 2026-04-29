#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${FARAMESH_NODE_REAL_DIR:-$ROOT_DIR/.tmp/node-autopatch-real}"
BIN_PATH="${FARAMESH_NODE_REAL_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_NODE_REAL_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_NODE_REAL_DATA:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_NODE_REAL_POLICY:-$RUN_DIR/node_autopatch_policy.fpl}"
DAEMON_LOG="${FARAMESH_NODE_REAL_DAEMON_LOG:-$RUN_DIR/daemon.log}"
NODE_SCRIPT_PATH="${FARAMESH_NODE_REAL_SCRIPT:-$RUN_DIR/node_agent.js}"
NODE_OUTPUT_PATH="${FARAMESH_NODE_REAL_OUTPUT:-$RUN_DIR/node_agent_output.log}"
NODE_FALLBACK_SCRIPT_PATH="${FARAMESH_NODE_REAL_FALLBACK_SCRIPT:-$RUN_DIR/node_fallback.js}"
NODE_FALLBACK_OUTPUT_PATH="${FARAMESH_NODE_REAL_FALLBACK_OUTPUT:-$RUN_DIR/node_fallback_output.log}"
SPIFFE_SOCKET_PATH="${FARAMESH_NODE_REAL_SPIFFE_SOCKET:-$RUN_DIR/spiffe.sock}"
INTEGRITY_MANIFEST_PATH="${FARAMESH_NODE_REAL_INTEGRITY_MANIFEST:-$RUN_DIR/integrity.json}"
BUILDINFO_EXPECTED_PATH="${FARAMESH_NODE_REAL_BUILDINFO_EXPECTED:-$RUN_DIR/buildinfo.json}"
BUILDINFO_STDERR_PATH="${FARAMESH_NODE_REAL_BUILDINFO_STDERR:-$RUN_DIR/buildinfo.stderr.log}"
NODE_RUN_STDERR_PATH="${FARAMESH_NODE_REAL_RUN_STDERR:-$RUN_DIR/node_run.stderr.log}"

AGENT_ID="${FARAMESH_NODE_REAL_AGENT_ID:-node-autopatch-e2e}"
DPR_HMAC_KEY="${FARAMESH_NODE_REAL_DPR_HMAC:-node-autopatch-replay-hmac}"

show_debug_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    echo "--- $path ---"
    tail -n 200 "$path"
  fi
}

cleanup() {
  local status=$?
  set +e
  if [[ "$status" -ne 0 ]]; then
    show_debug_file "$BUILDINFO_STDERR_PATH"
    show_debug_file "$NODE_RUN_STDERR_PATH"
    show_debug_file "$DAEMON_LOG"
    show_debug_file "$NODE_OUTPUT_PATH"
    show_debug_file "$NODE_FALLBACK_OUTPUT_PATH"
  fi
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
  return "$status"
}
trap cleanup EXIT

run_cmd() {
  echo "+ $*"
  "$@"
}

wait_for_daemon() {
  local attempts=100
  local delay_seconds=0.1

  for _ in $(seq 1 "$attempts"); do
    if "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
      echo "daemon exited before becoming ready"
      cat "$DAEMON_LOG"
      return 1
    fi
    sleep "$delay_seconds"
  done

  echo "daemon readiness timeout"
  cat "$DAEMON_LOG"
  return 1
}

for required in node npm python3 go; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required for the node autopatch harness" >&2
    exit 1
  fi
done

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$NODE_OUTPUT_PATH" "$NODE_FALLBACK_OUTPUT_PATH" "$INTEGRITY_MANIFEST_PATH" "$BUILDINFO_EXPECTED_PATH" "$BUILDINFO_STDERR_PATH" "$NODE_RUN_STDERR_PATH"

cat >"$POLICY_PATH" <<'FPL'
agent node-autopatch-e2e {
  default deny

  rules {
    permit http/get
    defer stripe/refund reason: "refund requires manual approval"
  }
}
FPL

cat >"$NODE_SCRIPT_PATH" <<'JS'
const autopatchPath = process.env.FARAMESH_NODE_AUTOPATCH_PATH;
if (!autopatchPath) {
  throw new Error("FARAMESH_NODE_AUTOPATCH_PATH is required");
}

const { installAutoPatch } = require(autopatchPath);

class FakeMCPServer {
  constructor() {
    this.handlers = new Map();
  }

  setRequestHandler(schema, handler) {
    const key = (schema && (schema.method || schema.name)) || "";
    this.handlers.set(key, handler);
  }

  async callTool(name, args) {
    const handler = this.handlers.get("tools/call");
    if (!handler) {
      throw new Error("tools/call handler not set");
    }
    return handler({ params: { name, arguments: args || {} } }, {});
  }
}

async function runStep(server, step, tool, args) {
  try {
    await server.callTool(tool, args);
    return { step, status: "executed" };
  } catch (err) {
    const message = String((err && err.message) || err || "unknown error");
    if (message.includes("Faramesh DENY")) {
      return { step, status: "denied", message };
    }
    if (message.includes("Faramesh DEFER")) {
      const match = message.match(/token=([^,\)\s]+)/);
      const token = match ? match[1] : "";
      return { step, status: "deferred", token, message };
    }
    return { step, status: "error", message };
  }
}

async function main() {
  const server = new FakeMCPServer();
  const patched = installAutoPatch(server);
  server.setRequestHandler({ method: "tools/call" }, async (request) => {
    return { ok: true, tool: request.params.name };
  });

  console.log(JSON.stringify({ event: "startup", patched }));

  const results = [];
  results.push(await runStep(server, "permit_http", "http/get", { url: "https://example.com" }));
  results.push(await runStep(server, "deny_shell", "shell/run", { command: "cat /etc/passwd" }));
  results.push(await runStep(server, "defer_approve", "stripe/refund", { amount: 700 }));
  results.push(await runStep(server, "defer_deny", "stripe/refund", { amount: 701 }));

  for (const result of results) {
    if (result.token) {
      console.log(JSON.stringify({ event: "token", step: result.step, token: result.token }));
    }
    console.log(JSON.stringify({ event: "step", ...result }));
  }
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
JS

cat >"$NODE_FALLBACK_SCRIPT_PATH" <<'JS'
const autopatchPath = process.env.FARAMESH_NODE_AUTOPATCH_PATH;
if (!autopatchPath) {
  throw new Error("FARAMESH_NODE_AUTOPATCH_PATH is required");
}

const { installAutoPatch } = require(autopatchPath);

class FakeMCPServer {
  constructor() {
    this.handlers = new Map();
  }

  setRequestHandler(schema, handler) {
    const key = (schema && (schema.method || schema.name)) || "";
    this.handlers.set(key, handler);
  }

  async callTool(name, args) {
    const handler = this.handlers.get("tools/call");
    if (!handler) {
      throw new Error("tools/call handler not set");
    }
    return handler({ params: { name, arguments: args || {} } }, {});
  }
}

async function main() {
  const server = new FakeMCPServer();
  const patched = installAutoPatch(server);
  server.setRequestHandler({ method: "tools/call" }, async () => ({ ok: true }));

  let failClosed = false;
  try {
    await server.callTool("http/get", { url: "https://example.com" });
  } catch (err) {
    const message = String((err && err.message) || err || "unknown error");
    if (message.includes("Faramesh governance error")) {
      failClosed = true;
    } else {
      throw err;
    }
  }

  console.log(JSON.stringify({ event: "fallback", patched, fail_closed: failClosed }));
  if (!patched || !failClosed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
JS

run_cmd npm --prefix "$ROOT_DIR/sdk/node" ci --no-audit --no-fund
run_cmd npm --prefix "$ROOT_DIR/sdk/node" run build

run_cmd go build -o "$BIN_PATH" ./cmd/faramesh
run_cmd "$BIN_PATH" verify manifest-generate --base-dir "$ROOT_DIR" --output "$INTEGRITY_MANIFEST_PATH" "$POLICY_PATH"
echo "+ $BIN_PATH verify buildinfo --emit > $BUILDINFO_EXPECTED_PATH"
"$BIN_PATH" verify buildinfo --emit >"$BUILDINFO_EXPECTED_PATH" 2>"$BUILDINFO_STDERR_PATH"

FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --dpr-hmac-key "$DPR_HMAC_KEY" \
  --strict-preflight \
  --integrity-manifest "$INTEGRITY_MANIFEST_PATH" \
  --integrity-base-dir "$ROOT_DIR" \
  --buildinfo-expected "$BUILDINFO_EXPECTED_PATH" \
  --spiffe-socket "$SPIFFE_SOCKET_PATH" \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

wait_for_daemon

echo "+ $BIN_PATH --daemon-socket $SOCKET_PATH run --enforce minimal -- node $NODE_SCRIPT_PATH"
FARAMESH_SOCKET="$SOCKET_PATH" \
FARAMESH_AGENT_ID="$AGENT_ID" \
FARAMESH_NODE_AUTOPATCH_PATH="$ROOT_DIR/sdk/node/dist/autopatch.js" \
"$BIN_PATH" --daemon-socket "$SOCKET_PATH" run --enforce minimal -- node "$NODE_SCRIPT_PATH" >"$NODE_OUTPUT_PATH" 2>"$NODE_RUN_STDERR_PATH"

TOKENS="$(python3 - "$NODE_OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
patched = False
steps = {}
tokens = {}

with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if payload.get("event") == "startup":
            patched = bool(payload.get("patched"))
        elif payload.get("event") == "step":
            steps[payload.get("step")] = payload.get("status")
        elif payload.get("event") == "token":
            tokens[payload.get("step")] = payload.get("token", "")

expected = {
    "permit_http": "executed",
    "deny_shell": "denied",
    "defer_approve": "deferred",
    "defer_deny": "deferred",
}

if not patched:
    raise SystemExit("node autopatch was not installed")

for step, want in expected.items():
    got = steps.get(step)
    if got != want:
        raise SystemExit(f"step {step} expected {want}, got {got}")

approve = tokens.get("defer_approve", "")
deny = tokens.get("defer_deny", "")
if not approve or not deny:
    raise SystemExit(f"missing defer tokens: {tokens}")

print(f"{approve} {deny}")
PY
)"

read -r DEFER_APPROVE_TOKEN DEFER_DENY_TOKEN <<<"$TOKENS"

run_cmd "$BIN_PATH" agent approve "$DEFER_APPROVE_TOKEN" --socket "$SOCKET_PATH"
run_cmd "$BIN_PATH" agent deny "$DEFER_DENY_TOKEN" --socket "$SOCKET_PATH"

python3 - "$SOCKET_PATH" "$AGENT_ID" "$DEFER_APPROVE_TOKEN" "$DEFER_DENY_TOKEN" <<'PY'
import json
import socket
import sys
import time

socket_path = sys.argv[1]
agent_id = sys.argv[2]
approve_token = sys.argv[3]
deny_token = sys.argv[4]


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
            stable = send({"type": "poll_defer", "agent_id": agent_id, "defer_token": token})
            stable_status = str(stable.get("status", "")).lower()
            if stable_status != expected:
                raise RuntimeError(f"defer token {token} did not remain {expected}: {stable}")
            return
        time.sleep(0.1)
    raise RuntimeError(f"defer token {token} did not reach {expected}")


poll(approve_token, "approved")
poll(deny_token, "denied")
print("defer approval continuity checks passed")
PY

FARAMESH_NODE_AUTOPATCH_PATH="$ROOT_DIR/sdk/node/dist/autopatch.js" \
FARAMESH_SOCKET="$RUN_DIR/missing.sock" \
FARAMESH_BASE_URL="http://127.0.0.1:1" \
FARAMESH_RETRIES=0 \
FARAMESH_AGENT_ID="$AGENT_ID" \
node "$NODE_FALLBACK_SCRIPT_PATH" >"$NODE_FALLBACK_OUTPUT_PATH" 2>&1

python3 - "$NODE_FALLBACK_OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
ok = False
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if payload.get("event") == "fallback" and payload.get("patched") and payload.get("fail_closed"):
            ok = True
            break

if not ok:
    raise SystemExit("missing fallback fail-closed evidence")
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
    permit_http = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "shell/run%", "DENY"),
    )
    deny_shell = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and tool_id like ? and effect = ?",
        (agent_id, "stripe/refund%", "DEFER"),
    )
    defer_refund = cur.fetchone()[0]

    cur.execute(
        "select count(*) from dpr_records where agent_id = ? and record_hash is not null and record_hash != ''",
        (agent_id,),
    )
    with_record_hash = cur.fetchone()[0]

    return permit_http, deny_shell, defer_refund, with_record_hash


deadline = time.time() + 5.0
permit_http = 0
deny_shell = 0
defer_refund = 0
with_record_hash = 0

while True:
    permit_http, deny_shell, defer_refund, with_record_hash = read_counts()
    if permit_http >= 1 and deny_shell >= 1 and defer_refund >= 1 and with_record_hash >= 3:
        break
    if time.time() >= deadline:
        break
    time.sleep(0.1)

con.close()

if permit_http < 1:
    raise SystemExit("missing PERMIT DPR record for http/get")
if deny_shell < 1:
    raise SystemExit("missing DENY DPR record for shell/run")
if defer_refund < 1:
  raise SystemExit("missing DEFER DPR record for stripe/refund")
if with_record_hash < 3:
    raise SystemExit("missing DPR record_hash evidence")
PY

run_cmd "$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
run_cmd "$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --max-divergence 0 --strict-reason-parity --dpr-hmac-key "$DPR_HMAC_KEY"

echo "node autopatch real-stack harness passed"
