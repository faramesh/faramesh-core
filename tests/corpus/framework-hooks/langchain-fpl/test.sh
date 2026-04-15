#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
exec bash "$CORE_DIR/tests/langchain_single_agent_real_stack_fpl.sh"
