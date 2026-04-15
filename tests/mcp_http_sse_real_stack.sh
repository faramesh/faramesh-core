#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${FARAMESH_MCP_HTTP_DIR:-$ROOT_DIR/.tmp/mcp-http-sse}"
BIN_PATH="${FARAMESH_MCP_HTTP_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_MCP_HTTP_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_MCP_HTTP_DATA:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_MCP_HTTP_POLICY:-$RUN_DIR/policy.yaml}"
DAEMON_LOG="${FARAMESH_MCP_HTTP_DAEMON_LOG:-$RUN_DIR/daemon.log}"
UPSTREAM_LOG="${FARAMESH_MCP_HTTP_UPSTREAM_LOG:-$RUN_DIR/upstream.log}"
UPSTREAM_PORT_FILE="${FARAMESH_MCP_HTTP_UPSTREAM_PORT_FILE:-$RUN_DIR/upstream.port}"
UPSTREAM_SERVER_SCRIPT="${FARAMESH_MCP_HTTP_UPSTREAM_SCRIPT:-$RUN_DIR/upstream_server.py}"
SSE_FIRST_PATH="${FARAMESH_MCP_HTTP_SSE_FIRST:-$RUN_DIR/first.sse}"
SSE_SECOND_PATH="${FARAMESH_MCP_HTTP_SSE_SECOND:-$RUN_DIR/second.sse}"

cleanup() {
  set +e
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${UPSTREAM_PID:-}" ]]; then
    kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
    wait "$UPSTREAM_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

wait_for_daemon() {
  local attempts=100
  for _ in $(seq 1 "$attempts"); do
    if "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
      echo "daemon exited before ready"
      sed -n '1,200p' "$DAEMON_LOG"
      return 1
    fi
    sleep 0.1
  done
  echo "daemon readiness timeout"
  sed -n '1,200p' "$DAEMON_LOG"
  return 1
}

wait_for_upstream() {
  local attempts=100
  for _ in $(seq 1 "$attempts"); do
    if [[ -s "$UPSTREAM_PORT_FILE" ]]; then
      return 0
    fi
    if ! kill -0 "$UPSTREAM_PID" >/dev/null 2>&1; then
      echo "upstream exited before ready"
      sed -n '1,200p' "$UPSTREAM_LOG"
      return 1
    fi
    sleep 0.1
  done
  echo "upstream readiness timeout"
  sed -n '1,200p' "$UPSTREAM_LOG"
  return 1
}

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$UPSTREAM_LOG" "$UPSTREAM_PORT_FILE" "$SSE_FIRST_PATH" "$SSE_SECOND_PATH"
touch "$UPSTREAM_LOG"

cat >"$POLICY_PATH" <<'YAML'
faramesh-version: "1.0"
agent-id: "mcp-http-sse"
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
YAML

cat >"$UPSTREAM_SERVER_SCRIPT" <<'PY'
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log_path = sys.argv[1]
port_path = sys.argv[2]
get_calls = {"count": 0}

def log_event(payload):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0")).decode("utf-8")
        payload = json.loads(body)
        method = payload.get("method")
        tool_name = ((payload.get("params") or {}).get("name")) if isinstance(payload.get("params"), dict) else None
        log_event({
            "method": "POST",
            "path": self.path,
            "tool_name": tool_name,
        })
        resp = {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {"echo": True, "tool_name": tool_name, "upstream": True},
        }
        data = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        get_calls["count"] += 1
        call = get_calls["count"]
        log_event({
            "method": "GET",
            "path": self.path,
            "last_event_id": self.headers.get("Last-Event-ID", ""),
            "session_id": self.headers.get("Mcp-Session-Id", ""),
        })
        if call == 1:
            body = "id: evt-1\ndata: first\n\nid: evt-2\ndata: second\n\n"
        elif call == 2:
            body = "id: evt-3\ndata: third\n\n"
        else:
            body = "id: evt-x\ndata: extra\n\n"
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_path, "w", encoding="utf-8") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY

python3 "$UPSTREAM_SERVER_SCRIPT" "$UPSTREAM_LOG" "$UPSTREAM_PORT_FILE" >>"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!
wait_for_upstream
UPSTREAM_PORT="$(tr -d '\n' < "$UPSTREAM_PORT_FILE")"

GATEWAY_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

go build -o "$BIN_PATH" ./cmd/faramesh

"$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --mcp-proxy-port "$GATEWAY_PORT" \
  --mcp-target "http://127.0.0.1:$UPSTREAM_PORT" \
  --mcp-sse-replay-enabled \
  --mcp-sse-replay-max-events 32 \
  --mcp-sse-replay-max-age 1h \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
wait_for_daemon

PERMIT_BODY='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}'
DENY_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"danger/x","arguments":{}}}'

PERMIT_RESP="$(curl -sS -X POST "http://127.0.0.1:$GATEWAY_PORT/" -H 'Content-Type: application/json' -H 'Mcp-Session-Id: session-http' --data "$PERMIT_BODY")"
DENY_RESP="$(curl -sS -X POST "http://127.0.0.1:$GATEWAY_PORT/" -H 'Content-Type: application/json' -H 'Mcp-Session-Id: session-http' --data "$DENY_BODY")"

curl -sS "http://127.0.0.1:$GATEWAY_PORT/" -H 'Accept: text/event-stream' -H 'Mcp-Session-Id: session-replay' >"$SSE_FIRST_PATH"
curl -sS "http://127.0.0.1:$GATEWAY_PORT/" -H 'Accept: text/event-stream' -H 'Mcp-Session-Id: session-replay' -H 'Last-Event-ID: evt-1' >"$SSE_SECOND_PATH"

python3 - "$PERMIT_RESP" "$DENY_RESP" "$SSE_FIRST_PATH" "$SSE_SECOND_PATH" "$UPSTREAM_LOG" <<'PY'
import json
import sys

permit_resp, deny_resp, first_path, second_path, upstream_log = sys.argv[1:]

permit = json.loads(permit_resp)
if permit.get("result", {}).get("echo") is not True:
    raise SystemExit(f"permit path failed: {permit}")
deny = json.loads(deny_resp)
err = deny.get("error") or {}
if err.get("code") != -32003:
    raise SystemExit(f"deny path failed: {deny}")

first = open(first_path, "r", encoding="utf-8").read()
second = open(second_path, "r", encoding="utf-8").read()
if "id: evt-1" not in first or "id: evt-2" not in first:
    raise SystemExit(f"first SSE stream missing expected events: {first}")
if "id: evt-1" in second:
    raise SystemExit(f"second SSE stream should replay after evt-1 only: {second}")
if "id: evt-2" not in second or "id: evt-3" not in second:
    raise SystemExit(f"second SSE stream missing replay/live events: {second}")

events = [json.loads(line) for line in open(upstream_log, "r", encoding="utf-8") if line.strip()]
posts = [e for e in events if e.get("method") == "POST"]
gets = [e for e in events if e.get("method") == "GET"]
if len(posts) != 1 or posts[0].get("tool_name") != "safe/tool":
    raise SystemExit(f"expected only safe/tool to hit upstream, got {posts}")
if len(gets) < 2:
    raise SystemExit(f"expected at least two SSE upstream GETs, got {gets}")
if (gets[0].get("last_event_id") or "").strip() != "":
    raise SystemExit(f"first upstream GET should not receive Last-Event-ID: {gets[0]}")
if (gets[1].get("last_event_id") or "").strip() != "":
    raise SystemExit(f"gateway should consume Last-Event-ID before upstream replay GET: {gets[1]}")
PY

"$BIN_PATH" audit verify "$DATA_DIR/faramesh.db"
"$BIN_PATH" policy policy-replay --policy "$POLICY_PATH" --wal "$DATA_DIR/faramesh.wal" --max-divergence 0 --strict-reason-parity

echo "mcp http sse real-stack harness passed"
