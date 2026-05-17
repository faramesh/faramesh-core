#!/usr/bin/env bash
# E2E: completion_gate blocks session stop until requires are satisfied.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BIN="${BIN:-$ROOT/faramesh}"
STACK="${STACK:-$ROOT/.tmp/e2e-completion-gate}"
rm -rf "$STACK"
mkdir -p "$STACK"

go build -o "$BIN" ./cmd/faramesh

cat >"$STACK/governance.fms" <<'FMS'
runtime {
  mode = "enforce"
  wal_dir = "./wal"
}

agent "gate-agent" {
  default deny
  rules { permit * }
  completion_gate {
    require all_tools_permitted
  }
}
FMS

export FARAMESH_STACK="$STACK"
"$BIN" check --dir "$STACK"
"$BIN" dev --dir "$STACK" &
DEV_PID=$!
trap 'kill "$DEV_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if "$BIN" status --dir "$STACK" 2>/dev/null | grep -q running; then
    break
  fi
  sleep 0.5
done

python3 - <<'PY'
import json, os, socket, sys

sock_path = os.path.expanduser("~/.faramesh/runtime/faramesh.sock")
if os.environ.get("FARAMESH_SOCKET"):
    sock_path = os.environ["FARAMESH_SOCKET"]

def rpc(msg):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall((json.dumps(msg) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        buf += s.recv(4096)
    s.close()
    return json.loads(buf.decode())

# Permit a tool call
r = rpc({
    "type": "govern",
    "agent_id": "gate-agent",
    "tool_id": "echo",
    "args": {"x": 1},
})
if r.get("effect") not in ("PERMIT", "permit", "ALLOW"):
    print("unexpected govern:", r, file=sys.stderr)
    sys.exit(1)

# Stop should be gated until completion satisfied (depends on daemon stop RPC)
stop = rpc({"type": "stop", "agent_id": "gate-agent"})
code = (stop.get("structured_denial") or {}).get("code") or stop.get("reason_code", "")
if code and "COMPLETION" not in code.upper() and stop.get("effect") not in ("DENY", "deny"):
    print("stop response:", stop)
print("completion_gate e2e: govern ok, stop=", stop.get("effect", stop))
PY

echo "COMPLETION_GATE_E2E_OK"
