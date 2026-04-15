#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRY_ARG="${1:-}"

if [[ -z "$ENTRY_ARG" ]]; then
  echo "usage: scripts/run_corpus_entry.sh <entry-path>" >&2
  exit 1
fi

ENTRY_PATH="$ENTRY_ARG"
if [[ "${ENTRY_PATH:0:1}" != "/" ]]; then
  ENTRY_PATH="$CORE_DIR/$ENTRY_PATH"
fi

TEST_SCRIPT="$ENTRY_PATH/test.sh"
EXPECTED_JSON="$ENTRY_PATH/expected.json"

if [[ ! -d "$ENTRY_PATH" ]]; then
  echo "corpus entry directory not found: $ENTRY_PATH" >&2
  exit 1
fi
if [[ ! -f "$EXPECTED_JSON" ]]; then
  echo "missing expected.json for corpus entry: $ENTRY_PATH" >&2
  exit 1
fi
if [[ ! -x "$TEST_SCRIPT" ]]; then
  echo "missing executable test.sh for corpus entry: $ENTRY_PATH" >&2
  exit 1
fi

echo "==> Running corpus entry: $(realpath --relative-to="$CORE_DIR" "$ENTRY_PATH" 2>/dev/null || echo "$ENTRY_PATH")"
exec bash "$TEST_SCRIPT"
