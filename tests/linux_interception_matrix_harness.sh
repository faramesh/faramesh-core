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
rm -f "$BIN_PATH" "$REPORT_PATH" "$ENV_PATH"

run_cmd go build -o "$BIN_PATH" ./cmd/faramesh

OPENAI_API_KEY="should-never-leak" \
FARAMESH_SOCKET="/tmp/faramesh-linux-matrix.sock" \
"$BIN_PATH" run --enforce "$PROFILE" --broker -- /usr/bin/env >"$ENV_PATH" 2>"$REPORT_PATH"

assert_contains "Faramesh Enforcement Report" "$REPORT_PATH"
assert_contains "Framework auto-patch (FARAMESH_AUTOLOAD)" "$REPORT_PATH"
assert_contains "Credential broker (stripped:" "$REPORT_PATH"
assert_contains "seccomp-BPF (immutable)" "$REPORT_PATH"
assert_contains "Landlock LSM (filesystem)" "$REPORT_PATH"
assert_contains "Network namespace (iptables)" "$REPORT_PATH"
assert_contains "Trust level:" "$REPORT_PATH"

assert_contains "FARAMESH_AUTOLOAD=1" "$ENV_PATH"
assert_contains "FARAMESH_TRUST_LEVEL=" "$ENV_PATH"
assert_not_contains "OPENAI_API_KEY=" "$ENV_PATH"

if [[ "$PROFILE" == "minimal" ]]; then
  assert_contains "seccomp-BPF (immutable) (skipped)" "$REPORT_PATH"
  assert_contains "Landlock LSM (filesystem) (skipped)" "$REPORT_PATH"
fi

if [[ "$(id -u)" != "0" ]]; then
  assert_contains "Network namespace (iptables) (skipped)" "$REPORT_PATH"
fi

echo "linux interception matrix harness passed (profile=$PROFILE)"
