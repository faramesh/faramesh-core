#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

# CI portability: prefer real-stack when Vault CLI is available, otherwise run
# the deterministic governed smoke harness for framework interception checks.
if command -v vault >/dev/null 2>&1; then
	exec bash "$CORE_DIR/tests/langchain_single_agent_real_stack.sh"
fi

echo "vault CLI unavailable; falling back to langchain_single_agent_governed.sh" >&2
exec bash "$CORE_DIR/tests/langchain_single_agent_governed.sh"
