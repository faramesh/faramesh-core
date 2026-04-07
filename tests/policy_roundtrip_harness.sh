#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${FARAMESH_POLICY_ROUNDTRIP_DIR:-$ROOT_DIR/.tmp/policy-roundtrip}"

run_cmd() {
  echo "+ $*"
  "$@"
}

mkdir -p "$RUN_DIR"
LOSSLESS_YAML="$RUN_DIR/lossless.yaml"
LOSSLESS_DECOMPILED="$RUN_DIR/lossless.decompiled.fpl"
LOSSY_YAML="$RUN_DIR/lossy.yaml"
LOSSY_FPL="$RUN_DIR/lossy.decompiled.fpl"
LOSSY_WARNINGS="$RUN_DIR/lossy.warnings.log"
LOSSY_STRICT_ERROR="$RUN_DIR/lossy.strict.error.log"

rm -f "$LOSSLESS_YAML" "$LOSSLESS_DECOMPILED" "$LOSSY_YAML" "$LOSSY_FPL" "$LOSSY_WARNINGS" "$LOSSY_STRICT_ERROR"

cat >"$LOSSLESS_YAML" <<'YAML'
faramesh-version: "1.0"
agent-id: "lossless-agent"
default_effect: deny
vars:
  region: us-east-1
rules:
  - id: allow-http
    effect: permit
    match:
      tool: http/get
      when: "args.host != nil"
    notify: ops
    reason: allow safe http reads
YAML

run_cmd go run ./cmd/faramesh policy validate "$LOSSLESS_YAML"
echo "+ go run ./cmd/faramesh policy decompile --strict-lossless $LOSSLESS_YAML > $LOSSLESS_DECOMPILED"
go run ./cmd/faramesh policy decompile --strict-lossless "$LOSSLESS_YAML" >"$LOSSLESS_DECOMPILED"
run_cmd go run ./cmd/faramesh policy validate "$LOSSLESS_DECOMPILED"

if ! grep -Fq "agent lossless-agent" "$LOSSLESS_DECOMPILED"; then
  echo "expected lossless decompile to preserve agent id"
  cat "$LOSSLESS_DECOMPILED"
  exit 1
fi

if ! grep -Fq "permit http/get when args.host != nil" "$LOSSLESS_DECOMPILED"; then
  echo "expected lossless decompile to preserve permit rule"
  cat "$LOSSLESS_DECOMPILED"
  exit 1
fi

run_cmd go run ./cmd/faramesh policy test "$LOSSLESS_DECOMPILED" --tool http/get --args '{"host":"example.com"}'

cat >"$LOSSY_YAML" <<'YAML'
faramesh-version: "1.0"
agent-id: "lossy-agent"
default_effect: deny
rules:
  - id: defer-high-refund
    effect: defer
    match:
      tool: stripe/refund
      when: "args.amount > 100"
context_guards:
  - source: account
    endpoint: https://context.internal/account
    required_fields:
      - tier
    on_missing: deny
cross_session_guards:
  - scope: principal
    tool_pattern: "db/*"
    metric: call_count
    window: "24h"
    max_unique_records: 5
    on_exceed: deny
YAML

echo "+ go run ./cmd/faramesh policy decompile $LOSSY_YAML > $LOSSY_FPL"
go run ./cmd/faramesh policy decompile "$LOSSY_YAML" >"$LOSSY_FPL" 2>"$LOSSY_WARNINGS"
run_cmd go run ./cmd/faramesh policy validate "$LOSSY_FPL"

if ! grep -Fq "conversion warnings (lossy fields):" "$LOSSY_WARNINGS"; then
  echo "expected lossy conversion warnings in $LOSSY_WARNINGS"
  cat "$LOSSY_WARNINGS"
  exit 1
fi

if ! grep -Fq "required_fields" "$LOSSY_WARNINGS"; then
  echo "expected required_fields lossy warning"
  cat "$LOSSY_WARNINGS"
  exit 1
fi

set +e
echo "+ go run ./cmd/faramesh policy decompile --strict-lossless $LOSSY_YAML"
go run ./cmd/faramesh policy decompile --strict-lossless "$LOSSY_YAML" > /dev/null 2>"$LOSSY_STRICT_ERROR"
STRICT_EXIT=$?
set -e

if [[ "$STRICT_EXIT" -eq 0 ]]; then
  echo "expected strict-lossless decompile to fail for lossy policy"
  exit 1
fi

if ! grep -Fq "lossy conversion blocked by --strict-lossless" "$LOSSY_STRICT_ERROR"; then
  echo "expected strict-lossless failure reason"
  cat "$LOSSY_STRICT_ERROR"
  exit 1
fi

echo "policy roundtrip harness passed"
