#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN_PATH="${FARAMESH_BIN:-$ROOT_DIR/.tmp/faramesh-e2e}"
SOCKET_PATH="${FARAMESH_E2E_SOCKET:-$ROOT_DIR/.tmp/faramesh-e2e.sock}"
DATA_DIR="${FARAMESH_E2E_DATA_DIR:-$ROOT_DIR/.tmp/faramesh-e2e-data}"
POLICY_PATH="${FARAMESH_E2E_POLICY:-$ROOT_DIR/policies/demo.fpl}"
DAEMON_LOG="${FARAMESH_E2E_LOG:-$ROOT_DIR/.tmp/faramesh-e2e-daemon.log}"
SPIFFE_SOCKET_PATH="${FARAMESH_E2E_SPIFFE_SOCKET:-$ROOT_DIR/.tmp/faramesh-spiffe.sock}"
INTEGRITY_MANIFEST_PATH="${FARAMESH_E2E_INTEGRITY_MANIFEST:-$ROOT_DIR/.tmp/faramesh-e2e-manifest.json}"
BUILDINFO_EXPECTED_PATH="${FARAMESH_E2E_BUILDINFO_EXPECTED:-$ROOT_DIR/.tmp/faramesh-e2e-buildinfo.json}"
CREDENTIAL_POLICY_PATH="${FARAMESH_E2E_CREDENTIAL_POLICY:-$ROOT_DIR/.tmp/faramesh-e2e-credential-required.yaml}"
PRINCIPAL_POLICY_PATH="${FARAMESH_E2E_PRINCIPAL_POLICY:-$ROOT_DIR/.tmp/faramesh-e2e-principal-required.yaml}"

AGENT_ID="e2e-agent"
CREDENTIAL_NAME="stripe-e2e"

cleanup() {
  set +e
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
  rm -f "$CREDENTIAL_POLICY_PATH" "$PRINCIPAL_POLICY_PATH"
}
trap cleanup EXIT

run_cmd() {
  echo "+ $*"
  "$@"
}

expect_cmd_fail() {
  local expected_substr="$1"
  shift

  echo "+ (expect-fail) $*"
  local output=""
  if output="$($@ 2>&1)"; then
    echo "expected command to fail, but it succeeded"
    echo "command: $*"
    echo "$output"
    return 1
  fi

  echo "$output"
  if [[ -n "$expected_substr" ]] && [[ "$output" != *"$expected_substr"* ]]; then
    echo "expected failure output to contain: $expected_substr"
    return 1
  fi
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

mkdir -p "$(dirname "$BIN_PATH")"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$INTEGRITY_MANIFEST_PATH" "$BUILDINFO_EXPECTED_PATH" "$CREDENTIAL_POLICY_PATH" "$PRINCIPAL_POLICY_PATH"

cat >"$CREDENTIAL_POLICY_PATH" <<'YAML'
faramesh-version: "1.0"
agent-id: "e2e-agent"
tools:
  stripe/refund:
    tags:
      - credential:required
rules:
  - id: allow-all
    match:
      tool: "*"
    effect: permit
default_effect: deny
YAML

cat >"$PRINCIPAL_POLICY_PATH" <<'YAML'
faramesh-version: "1.0"
agent-id: "e2e-agent"
rules:
  - id: principal-required
    match:
      tool: "*"
      when: principal.verified == true
    effect: permit
default_effect: deny
YAML

go build -o "$BIN_PATH" ./cmd/faramesh

# Note: onboard CLI subcommand has been removed
echo "Skipping removed CLI: 'onboard' subcommand not present in current faramesh"

run_cmd "$BIN_PATH" verify manifest-generate --base-dir "$ROOT_DIR" --output "$INTEGRITY_MANIFEST_PATH" "$POLICY_PATH"
"$BIN_PATH" verify buildinfo --emit >"$BUILDINFO_EXPECTED_PATH"

FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --strict-preflight \
  --integrity-manifest "$INTEGRITY_MANIFEST_PATH" \
  --integrity-base-dir "$ROOT_DIR" \
  --buildinfo-expected "$BUILDINFO_EXPECTED_PATH" \
  --spiffe-socket "$SPIFFE_SOCKET_PATH" \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

wait_for_daemon

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status

# Core socket JSON-RPC govern validation
# Deprecated CLI subcommands (session, model, identity, credential, provenance, incident, compensate) have been removed
echo "Validating core socket JSON-RPC govern protocol"

python3 - "$SOCKET_PATH" <<'PYTHON_VALIDATE'
import json
import socket
import sys

socket_path = sys.argv[1]

def send_json_rpc(payload):
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
        raise RuntimeError("empty response from daemon socket")
    return json.loads(data.decode("utf-8").strip())

# Test Python-style govern call
python_style = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "govern",
    "params": {
        "agent_id": "auto-patched",
        "tool_id": "http/get",
        "args": {"url": "https://example.org"},
    },
}
resp = send_json_rpc(python_style)
if resp.get("jsonrpc") != "2.0" or "result" not in resp:
    raise RuntimeError(f"invalid python-style response: {resp}")
if not str(resp["result"].get("effect", "")).strip():
    raise RuntimeError(f"missing effect in python-style response: {resp}")

# Test Node.js-style govern call
node_style = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "govern",
    "params": {
        "agent_id": "auto-patched",
        "tool": "http",
        "operation": "get",
        "args": {"url": "https://example.com"},
    },
}
resp2 = send_json_rpc(node_style)
if resp2.get("jsonrpc") != "2.0" or "result" not in resp2:
    raise RuntimeError(f"invalid node-style response: {resp2}")
if not str(resp2["result"].get("effect", "")).strip():
    raise RuntimeError(f"missing effect in node-style response: {resp2}")

print("socket JSON-RPC govern protocol validation passed")
PYTHON_VALIDATE

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status

echo "socket-only E2E acceptance completed (core socket JSON-RPC govern validation)"
