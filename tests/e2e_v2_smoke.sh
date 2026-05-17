#!/usr/bin/env bash
# End-to-end smoke test for Faramesh v2 stack workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/faramesh}"
REGISTRY_URL="${FARAMESH_REGISTRY_URL:-http://127.0.0.1:9876}"
REG_LISTEN="${REG_LISTEN:-127.0.0.1:9876}"
STACK="$(mktemp -d)"
REG_PID=""

cleanup() {
  if [[ -n "$REG_PID" ]] && kill -0 "$REG_PID" 2>/dev/null; then
    kill "$REG_PID" 2>/dev/null || true
  fi
  rm -rf "$STACK"
}
trap cleanup EXIT

(cd "$ROOT" && go build -o "$BIN" ./cmd/faramesh)

REG_ROOT="$(cd "$ROOT/../faramesh-registry" 2>/dev/null && pwd || true)"
REGISTRY_OK=0
if curl -sf "$REGISTRY_URL/.well-known/faramesh.json" >/dev/null 2>&1; then
  REGISTRY_OK=1
elif [[ -n "$REG_ROOT" && -f "$REG_ROOT/catalog/catalog.json" ]]; then
  (cd "$REG_ROOT" && go run ./cmd/registry -catalog catalog -listen "$REG_LISTEN") &
  REG_PID=$!
  sleep 2
  if curl -sf "$REGISTRY_URL/.well-known/faramesh.json" >/dev/null 2>&1; then
    REGISTRY_OK=1
  fi
fi

export FARAMESH_REGISTRY_URL="$REGISTRY_URL"

cd "$STACK"
"$BIN" init --non-interactive --offline
test -f governance.fms

"$BIN" check --dir "$STACK"
"$BIN" plan --dir "$STACK"

# Registry fetch smoke (optional; requires faramesh-registry on REGISTRY_URL)
if [[ "$REGISTRY_OK" == 1 ]]; then
  curl -sf "$REGISTRY_URL/v1/frameworks/langgraph/versions/1.0.0" | grep -q policy_fpl || {
    echo "registry: framework fetch failed" >&2
    exit 1
  }
  curl -sf "$REGISTRY_URL/v1/policies/faramesh%2Fdemo/versions/0.1.0" | grep -q policy_fpl || {
    echo "registry: policy fetch failed" >&2
    exit 1
  }
fi

echo "e2e v2 smoke: OK"
