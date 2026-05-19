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
LOSSLESS_FPL="$RUN_DIR/lossless.fpl"
rm -f "$LOSSLESS_FPL"

cp "$ROOT_DIR/../fpl-lang/conformance/valid/basic-agent.fpl" "$LOSSLESS_FPL"

echo "Parsing lossless FPL with reference parser"
(cd "$ROOT_DIR/../fpl-lang/reference/go" && go run ./cmd/fplparse "$LOSSLESS_FPL") >/dev/null

echo "+ Skipping decompile/test steps (policy CLI removed). Parsing validated."

echo "policy roundtrip harness: parse-only validation passed (policy CLI removed)"
