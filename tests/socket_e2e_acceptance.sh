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

# Validate strict onboarding fail-closed behavior before daemon startup.
expect_cmd_fail "Policy requires brokered credentials" env FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" onboard --strict=true --policy "$CREDENTIAL_POLICY_PATH" --interactive=false --spiffe-socket "$SPIFFE_SOCKET_PATH" --credential-profile production --credential-backend auto
run_cmd env FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" onboard --strict=true --policy "$CREDENTIAL_POLICY_PATH" --interactive=false --spiffe-socket "$SPIFFE_SOCKET_PATH" --credential-profile production --credential-backend local-vault

expect_cmd_fail "configured but not ready" env FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" onboard --strict=true --policy "$PRINCIPAL_POLICY_PATH" --idp-provider okta --interactive=false --spiffe-socket "$SPIFFE_SOCKET_PATH"
run_cmd env FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" onboard --strict=true --policy "$PRINCIPAL_POLICY_PATH" --idp-provider default --interactive=false --spiffe-socket "$SPIFFE_SOCKET_PATH"

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

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session open "$AGENT_ID" --budget 25 --ttl 30m
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session list --agent "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session budget "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session budget "$AGENT_ID" --set 10
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session purpose declare "$AGENT_ID" support
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session purpose list "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session inspect "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session reset "$AGENT_ID" --counter all

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" model register e2e-model --fingerprint abc123 --provider openai --version 2026-03
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" model list
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" model verify --agent "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" model consistency --agent "$AGENT_ID" --window 24h
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" model alert "$AGENT_ID"

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" provenance sign --agent "$AGENT_ID" --model gpt-4o --framework langgraph --tools read,write --key k1
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" provenance list
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" provenance verify "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" provenance inspect "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" provenance diff "$AGENT_ID"

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity verify --spiffe "spiffe://example.org/agent/$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity trust --domain example.org --bundle bundle.pem
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity attest --workload payments-worker
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity federation add --idp https://idp.example --client-id cid --scope openid
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity federation list
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity whoami
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity trust-level
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" identity federation revoke --idp https://idp.example

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential register "$CREDENTIAL_NAME" --key sk_live_x --scope payments --max-scope payments:write
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential list
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential inspect "$CREDENTIAL_NAME"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential rotate "$CREDENTIAL_NAME" --key sk_live_new
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential health
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential map
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential audit "$CREDENTIAL_NAME" --window 24h
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" credential revoke "$CREDENTIAL_NAME"

INCIDENT_OUTPUT="$("$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident declare --agent "$AGENT_ID" --severity high --reason risk)"
echo "$INCIDENT_OUTPUT"
INCIDENT_ID="$(INCIDENT_OUTPUT="$INCIDENT_OUTPUT" python3 - <<'PY'
import json
import os
import re

text = os.environ.get("INCIDENT_OUTPUT", "")
match = re.search(r"\{[\s\S]*\}", text)
if not match:
    raise SystemExit(1)
payload = json.loads(match.group(0))
print(payload.get("id", ""))
PY
)"
if [[ -z "$INCIDENT_ID" ]]; then
  echo "failed to extract incident id from output"
  exit 1
fi
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident list
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident inspect "$INCIDENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident evidence "$INCIDENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident playbook "$INCIDENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident isolate "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" incident resolve "$INCIDENT_ID"

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" compensate apply cmp-1
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" compensate status cmp-1
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" compensate inspect cmp-1
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" compensate retry cmp-1 --from-step rollback
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" compensate list

python3 - "$SOCKET_PATH" <<'PY'
import json
import socket
import sys

socket_path = sys.argv[1]


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

node_style = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "govern",
    "params": {
        "agent_id": "auto-patched",
        "tool": "http",
        "operation": "get",
        "args": {"url": "https://example.com"},
    },
}
node_resp = send(node_style)
if node_resp.get("jsonrpc") != "2.0" or "result" not in node_resp:
    raise RuntimeError(f"invalid node-style response: {node_resp}")
if not str(node_resp["result"].get("effect", "")).strip():
    raise RuntimeError(f"missing effect in node-style response: {node_resp}")

python_style = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "govern",
    "params": {
        "agent_id": "auto-patched",
        "tool_id": "http/get",
        "args": {"url": "https://example.org"},
    },
}
python_resp = send(python_style)
if python_resp.get("jsonrpc") != "2.0" or "result" not in python_resp:
    raise RuntimeError(f"invalid python-style response: {python_resp}")
if not str(python_resp["result"].get("effect", "")).strip():
    raise RuntimeError(f"missing effect in python-style response: {python_resp}")

print("json-rpc govern compatibility checks passed")
PY

run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" session close "$AGENT_ID"
run_cmd "$BIN_PATH" --daemon-socket "$SOCKET_PATH" status

echo "socket-only E2E acceptance completed"
