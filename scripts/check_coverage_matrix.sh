#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="${1:-$CORE_DIR/tests/corpus}"

python3 "$CORE_DIR/scripts/corpus_contract_check.py" "$CORPUS_DIR"
bash "$CORE_DIR/scripts/generate_coverage_matrix.sh" "$CORPUS_DIR"

git -C "$CORE_DIR" diff --exit-code -- \
  "tests/corpus/coverage-matrix.json" \
  "tests/corpus/coverage-matrix.md"
