#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export FARAMESH_LANGCHAIN_REAL_POLICY="${FARAMESH_LANGCHAIN_REAL_POLICY:-$CORE_DIR/policies/langchain_single_agent.fpl}"
export FARAMESH_LANGCHAIN_REAL_IDP_PROVIDER="${FARAMESH_LANGCHAIN_REAL_IDP_PROVIDER:-default}"

bash "$CORE_DIR/tests/langchain_single_agent_real_stack.sh"
