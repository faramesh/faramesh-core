#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${FARAMESH_LANGCHAIN_RUN_DIR:-$ROOT_DIR/.tmp/langchain-single}"
BIN_PATH="${FARAMESH_LANGCHAIN_BIN:-$RUN_DIR/faramesh}"
SOCKET_PATH="${FARAMESH_LANGCHAIN_SOCKET:-$RUN_DIR/faramesh.sock}"
DATA_DIR="${FARAMESH_LANGCHAIN_DATA_DIR:-$RUN_DIR/data}"
POLICY_PATH="${FARAMESH_LANGCHAIN_POLICY:-$ROOT_DIR/policies/default.fpl}"
DAEMON_LOG="${FARAMESH_LANGCHAIN_DAEMON_LOG:-$RUN_DIR/daemon.log}"
MANIFEST_PATH="${FARAMESH_LANGCHAIN_MANIFEST:-$RUN_DIR/integrity.json}"
BUILDINFO_PATH="${FARAMESH_LANGCHAIN_BUILDINFO:-$RUN_DIR/buildinfo.json}"
SPIFFE_SOCKET_PATH="${FARAMESH_LANGCHAIN_SPIFFE_SOCKET:-$RUN_DIR/spiffe.sock}"
AGENT_SCRIPT_PATH="${FARAMESH_LANGCHAIN_AGENT_SCRIPT:-$RUN_DIR/agent_single.py}"
AGENT_OUTPUT_PATH="${FARAMESH_LANGCHAIN_AGENT_OUTPUT:-$RUN_DIR/agent_output.log}"
AGENT_ID="${FARAMESH_LANGCHAIN_AGENT_ID:-langchain-single}"

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
  local attempts=80
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

resolve_python() {
  if [[ -n "${FARAMESH_LANGCHAIN_PYTHON:-}" ]]; then
    if [[ ! -x "$FARAMESH_LANGCHAIN_PYTHON" ]]; then
      echo "FARAMESH_LANGCHAIN_PYTHON is set but not executable: $FARAMESH_LANGCHAIN_PYTHON" >&2
      return 1
    fi
    echo "$FARAMESH_LANGCHAIN_PYTHON"
    return 0
  fi

  local existing="$ROOT_DIR/.tmp/langchain-e2e/.venv/bin/python"
  if [[ -x "$existing" ]]; then
    echo "$existing"
    return 0
  fi

  local venv_dir="$RUN_DIR/.venv"
  if [[ ! -x "$venv_dir/bin/python" ]]; then
    python3 -m venv "$venv_dir"
  fi

  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet --upgrade pip
  "$venv_dir/bin/pip" install --disable-pip-version-check --quiet "langchain>=1,<2" -e "$ROOT_DIR/sdk/python"
  echo "$venv_dir/bin/python"
}

mkdir -p "$RUN_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
rm -f "$SOCKET_PATH" "$DAEMON_LOG" "$AGENT_OUTPUT_PATH"

cat > "$AGENT_SCRIPT_PATH" <<'PY'
import json
import os

import faramesh.autopatch as autopatch
from langchain_core.tools import tool


@tool("http/get")
def http_get(url: str) -> str:
    """Fetch a URL and return a synthetic response."""
    return f"fetched:{url}"


def main() -> None:
    patched = autopatch.install()
    print(json.dumps({"patched_frameworks": patched, "socket": os.environ.get("FARAMESH_SOCKET")}))

    try:
        output = http_get.run({"url": "https://example.com"})
        print(json.dumps({"tool": "http/get", "result": "executed", "output": output}))
    except Exception as exc:
        print(json.dumps({"tool": "http/get", "result": "blocked", "error": str(exc)}))
        raise


if __name__ == "__main__":
    main()
PY

PYTHON_BIN="$(resolve_python)"


go build -o "$BIN_PATH" ./cmd/faramesh

"$BIN_PATH" verify manifest-generate --base-dir "$ROOT_DIR" --output "$MANIFEST_PATH" "$POLICY_PATH"
"$BIN_PATH" verify buildinfo --emit > "$BUILDINFO_PATH"

FARAMESH_SPIFFE_ID="spiffe://example.org/agent/$AGENT_ID" "$BIN_PATH" serve \
  --policy "$POLICY_PATH" \
  --socket "$SOCKET_PATH" \
  --data-dir "$DATA_DIR" \
  --strict-preflight \
  --integrity-manifest "$MANIFEST_PATH" \
  --integrity-base-dir "$ROOT_DIR" \
  --buildinfo-expected "$BUILDINFO_PATH" \
  --spiffe-socket "$SPIFFE_SOCKET_PATH" \
  --log-level warn >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

wait_for_daemon

FARAMESH_SOCKET="$SOCKET_PATH" FARAMESH_AGENT_ID="$AGENT_ID" \
  "$BIN_PATH" --daemon-socket "$SOCKET_PATH" run -- "$PYTHON_BIN" "$AGENT_SCRIPT_PATH" >"$AGENT_OUTPUT_PATH" 2>&1

python3 - "$AGENT_OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
patched = False
executed = False

with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if "patched_frameworks" in payload and "langchain" in payload.get("patched_frameworks", []):
            patched = True
        if payload.get("tool") == "http/get" and payload.get("result") == "executed":
            executed = True

if not patched:
    print("missing LangChain autopatch evidence")
    raise SystemExit(1)
if not executed:
    print("governed tool execution did not complete")
    raise SystemExit(1)
PY

python3 - "$DATA_DIR/faramesh.db" "$AGENT_ID" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
agent_id = sys.argv[2]

con = sqlite3.connect(db_path)
cur = con.cursor()
cur.execute(
    "select count(*) from dpr_records where agent_id = ? and tool_id = ? and effect = ?",
    (agent_id, "http/get", "PERMIT"),
)
count = cur.fetchone()[0]
con.close()

if count < 1:
    print("missing durable DPR record for governed call")
    raise SystemExit(1)
PY

echo "single-agent LangChain governance smoke passed"
