#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export FARAMESH_LANGGRAPH_REAL_POLICY="${FARAMESH_LANGGRAPH_REAL_POLICY:-$CORE_DIR/policies/langgraph_single_agent.fpl}"
export FARAMESH_LANGGRAPH_REAL_IDP_PROVIDER="${FARAMESH_LANGGRAPH_REAL_IDP_PROVIDER:-default}"

bash "$CORE_DIR/tests/langgraph_single_agent_real_stack.sh"
