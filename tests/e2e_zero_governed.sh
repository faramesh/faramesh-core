#!/usr/bin/env bash
# E2E: faramesh init → dev → GovernedToolSet defer → approve → apply notice
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${FARAMESH_E2E_DIR:-$(mktemp -d /tmp/faramesh-e2e-XXXXXX)}"
BIN="${FARAMESH_BIN:-$CORE_DIR/faramesh}"
PYTHON_SDK="${FARAMESH_PYTHON_SDK:-$CORE_DIR/../faramesh-python-sdk}"
SOCKET="${FARAMESH_SOCKET:-$HOME/.faramesh/runtime/faramesh.sock}"
AGENT_ID="$(basename "$RUN_DIR")-agent"

cleanup() {
  set +e
  [[ -n "${DEV_PID:-}" ]] && kill "$DEV_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> build CLI"
(cd "$CORE_DIR" && go build -o "$BIN" ./cmd/faramesh/)

echo "==> init stack in $RUN_DIR"
mkdir -p "$RUN_DIR"
(cd "$RUN_DIR" && "$BIN" init --non-interactive)

echo "==> patch governance.fms for defer send_email"
export FARAMESH_E2E_PATCH_DIR="$RUN_DIR"
python3 <<'PATCH'
from pathlib import Path
import os
p = Path(os.environ["FARAMESH_E2E_PATCH_DIR"]) / "governance.fms"
text = p.read_text()
if "defer send_email" not in text:
    text = text.replace("  rules {", "  rules {\n    defer send_email", 1)
p.write_text(text)
PATCH
(cd "$RUN_DIR" && "$BIN" check)

echo "==> faramesh dev (background)"
(cd "$RUN_DIR" && FARAMESH_DEV_MODE=1 "$BIN" dev) >"$RUN_DIR/dev.log" 2>&1 &
DEV_PID=$!
for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.2
done
[[ -S "$SOCKET" ]] || { echo "daemon socket missing"; cat "$RUN_DIR/dev.log"; exit 1; }

echo "==> python GovernedToolSet defer + approve"
PY="$RUN_DIR/.venv/bin/python"
python3 -m venv "$RUN_DIR/.venv"
"$RUN_DIR/.venv/bin/pip" install -q -e "$PYTHON_SDK" langchain-core 2>/dev/null || \
  "$RUN_DIR/.venv/bin/pip" install -q -e "$PYTHON_SDK"

export FARAMESH_SOCKET="$SOCKET"
export FARAMESH_AGENT_ID="$AGENT_ID"
export FARAMESH_E2E_RUN_DIR="$RUN_DIR"

"$PY" <<'PY'
import os
from langchain_core.tools import tool
from faramesh import GovernedToolSet, ToolDeniedException

@tool
def send_email(to: str) -> str:
    """Send an email (governed e2e test)."""
    return f"sent to {to}"

tools = GovernedToolSet([send_email], agent_id=os.environ["FARAMESH_AGENT_ID"])
try:
    tools[0].invoke({"to": "a@b.com"})
except ToolDeniedException as e:
    effect = (e.effect or "").upper()
    if effect not in ("DEFER", "PENDING", "ABSTAIN") and not e.defer_token:
        raise SystemExit(f"expected DEFER, got effect={effect!r} code={e.code!r}")
    token = e.defer_token or e.approval_id
    if not token:
        raise SystemExit("defer missing defer_token")
    import os
    open(os.path.join(os.environ["FARAMESH_E2E_RUN_DIR"], "defer.token"), "w").write(token)
    print("DEFER_OK", token)
else:
    raise SystemExit("expected ToolDeniedException on defer")
PY

DEFER_TOKEN="$(cat "$RUN_DIR/defer.token")"
echo "==> approvals list"
(cd "$RUN_DIR" && FARAMESH_SOCKET="$SOCKET" "$BIN" approvals list | tee "$RUN_DIR/approvals.txt")
(cd "$RUN_DIR" && FARAMESH_SOCKET="$SOCKET" "$BIN" approvals approve "$DEFER_TOKEN" --reason "e2e approved")
echo "APPROVE_OK $DEFER_TOKEN"

(cd "$RUN_DIR" && FARAMESH_SOCKET="$SOCKET" "$BIN" approvals show "$DEFER_TOKEN" | tee "$RUN_DIR/approval-show.txt")
grep -qi "approved" "$RUN_DIR/approval-show.txt" || exit 1
echo "SHOW_APPROVED_OK"

kill "$DEV_PID" 2>/dev/null || true
wait "$DEV_PID" 2>/dev/null || true
DEV_PID=

echo "==> apply platform notice"
set +e
APPLY_OUT="$(cd "$RUN_DIR" && "$BIN" apply 2>&1 | tee "$RUN_DIR/apply.log")"
set -e
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "$APPLY_OUT" | grep -qiE 'darwin|Seatbelt|enforcement|SDK/proxy' || {
    echo "apply platform notice missing on Darwin"; echo "$APPLY_OUT"; exit 1
  }
else
  echo "$APPLY_OUT" | grep -qiE 'enforcement|seccomp|Landlock' || {
    echo "apply platform notice missing"; echo "$APPLY_OUT"; exit 1
  }
fi
echo "APPLY_NOTICE_OK"

echo "==> pip install faramesh-sdk (PyPI) + GovernedToolSet from workspace"
PIP_PY="$(mktemp -d)/venv"
python3 -m venv "$PIP_PY"
"$PIP_PY/bin/pip" install -q faramesh-sdk 2>/dev/null || "$PIP_PY/bin/pip" install -q faramesh 2>/dev/null || true
"$PIP_PY/bin/pip" install -q -e "$PYTHON_SDK"
"$PIP_PY/bin/python" -c 'from faramesh import GovernedToolSet, ToolDeniedException; print("PIP_IMPORT_OK")'

echo "ALL_E2E_PASSED"
