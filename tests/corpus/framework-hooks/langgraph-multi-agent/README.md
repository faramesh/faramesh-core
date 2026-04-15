# langgraph-multi-agent

Purpose:

- Proves LangGraph execute-layer interception still enforces Faramesh multi-agent delegation controls.
- Exercises `multiagent/invoke_agent` through real `ToolNode` dispatch, not just direct pipeline unit tests.

Coverage:

- permit for declared target `worker-a`
- deny when `delegation_ttl` is missing
- deny for undeclared target `worker-c`
- defer for `worker-b` because the orchestrator manifest requires prior approval
- approve and deny both defer-token resolution paths
- approved resume of a routing-deferred invocation, including persisted `approval_envelope` audit evidence
- per-session max-invocation exhaustion for `worker-a`
- DPR persistence for all three deferred events plus `audit verify` and WAL replay parity

Harness:

- Delegates to `tests/langgraph_multi_agent_real_stack.sh`

Known limitations:

- Focuses on delegation governance through LangGraph `ToolNode`, not a full graph-of-graphs orchestration runtime
