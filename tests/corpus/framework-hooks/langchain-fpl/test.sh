#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

# CI reliability: use deterministic governed smoke on GitHub Actions.
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
	# Keep CI deterministic in repo-only checkouts that do not include the
	# external demo script consumed by the real-stack harness.
	exec bash "$CORE_DIR/tests/langchain_single_agent_governed.sh"
fi

exec bash "$CORE_DIR/tests/langchain_single_agent_real_stack_fpl.sh"
