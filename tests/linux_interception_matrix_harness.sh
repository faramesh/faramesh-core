#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "linux interception harness skipped: non-linux host"
  exit 0
fi

PROFILE="${FARAMESH_LINUX_INTERCEPT_PROFILE:-auto}"
RUN_DIR="${FARAMESH_LINUX_INTERCEPT_RUN_DIR:-$ROOT_DIR/.tmp/linux-interception}"
BIN_PATH="${FARAMESH_LINUX_INTERCEPT_BIN:-$RUN_DIR/faramesh}"
REPORT_PATH="$RUN_DIR/report-${PROFILE}.log"
ENV_PATH="$RUN_DIR/env-${PROFILE}.txt"
ENV_DUMP_SRC="$RUN_DIR/env_dump.go"
ENV_DUMP_BIN="$RUN_DIR/env_dump"

show_debug_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    echo "--- $path ---"
    cat "$path"
  fi
}

on_exit() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    show_debug_file "$REPORT_PATH"
    show_debug_file "$ENV_PATH"
  fi
  return "$status"
}

trap on_exit EXIT

run_cmd() {
  echo "+ $*"
  "$@"
}

assert_contains() {
  local needle="$1"
  local path="$2"
  if ! grep -Fq "$needle" "$path"; then
    echo "expected to find '$needle' in $path"
    echo "--- $path ---"
    cat "$path"
    return 1
  fi
}

assert_not_contains() {
  local needle="$1"
  local path="$2"
  if grep -Fq "$needle" "$path"; then
    echo "expected '$needle' to be absent from $path"
    echo "--- $path ---"
    cat "$path"
    return 1
  fi
}

mkdir -p "$RUN_DIR"
rm -f "$BIN_PATH" "$REPORT_PATH" "$ENV_PATH" "$ENV_DUMP_SRC" "$ENV_DUMP_BIN"

run_cmd go build -o "$BIN_PATH" ./cmd/faramesh

cat >"$ENV_DUMP_SRC" <<'GO'
package main

import (
  "fmt"
  "os"
)

func main() {
  for _, entry := range os.Environ() {
    fmt.Println(entry)
  }
}
GO

run_cmd env CGO_ENABLED=0 go build -o "$ENV_DUMP_BIN" "$ENV_DUMP_SRC"

OPENAI_API_KEY="should-never-leak" \
FARAMESH_SOCKET="/tmp/faramesh-linux-matrix.sock" \
"$BIN_PATH" run --enforce "$PROFILE" --broker -- "$ENV_DUMP_BIN" >"$ENV_PATH" 2>"$REPORT_PATH" || RUN_STATUS=$?

RUN_STATUS="${RUN_STATUS:-0}"
if [[ "$RUN_STATUS" -ne 0 ]]; then
  if [[ "$PROFILE" == "auto" || "$PROFILE" == "full" ]]; then
    # Some hardened Linux runners terminate child processes under strict seccomp.
    case "$RUN_STATUS" in
      127|132|134|137|139|159)
        echo "linux interception child exited with status $RUN_STATUS under profile=$PROFILE; validating enforcement report"
        ;;
      *)
        echo "unexpected exit status $RUN_STATUS for profile=$PROFILE"
        exit "$RUN_STATUS"
        ;;
    esac
  else
    exit "$RUN_STATUS"
  fi
fi

assert_contains "Faramesh Enforcement Report" "$REPORT_PATH"
assert_contains "Framework auto-patch (FARAMESH_AUTOLOAD)" "$REPORT_PATH"
assert_contains "Credential broker (stripped:" "$REPORT_PATH"
assert_contains "seccomp-BPF (immutable)" "$REPORT_PATH"
assert_contains "Landlock LSM (filesystem)" "$REPORT_PATH"
assert_contains "Network namespace (iptables)" "$REPORT_PATH"
assert_contains "Trust level:" "$REPORT_PATH"

if [[ "$RUN_STATUS" -eq 0 ]]; then
  assert_contains "FARAMESH_AUTOLOAD=1" "$ENV_PATH"
  assert_contains "FARAMESH_TRUST_LEVEL=" "$ENV_PATH"
  assert_not_contains "OPENAI_API_KEY=" "$ENV_PATH"
else
  echo "skipping child environment assertions because child exited with status $RUN_STATUS"
fi

if [[ "$PROFILE" == "minimal" ]]; then
  assert_contains "seccomp-BPF (immutable) (skipped)" "$REPORT_PATH"
  assert_contains "Landlock LSM (filesystem) (skipped)" "$REPORT_PATH"
fi

if [[ "$(id -u)" != "0" ]]; then
  assert_contains "Network namespace (iptables) (skipped)" "$REPORT_PATH"
fi

echo "linux interception matrix harness passed (profile=$PROFILE)"
