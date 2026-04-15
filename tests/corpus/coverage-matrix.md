# Coverage Matrix

- Corpus root: `tests/corpus`
- Entries: 15
- Passing: 10
- WIP: 5

- Replay parity asserted: 10

| Entry | Status | Tier | Framework | Attachable | Governable | Policy Visible | Credential Brokered | Shell | Network | MCP | Audit | Replay | Hook | Pre-exec | Known Gaps |
|-------|--------|------|-----------|------------|------------|----------------|---------------------|-------|---------|-----|-------|--------|------|----------|------------|
| `framework-hooks/deepagents-governed` | passing | A | deepagents | yes | yes | yes | no | yes | no | no | yes | yes | framework_autopatch | yes | live model invocation is optional and skipped when OPENROUTER_API_KEY is absent |
| `framework-hooks/langchain-fpl` | passing | A | langchain | yes | yes | yes | yes | yes | yes | no | yes | yes | framework_autopatch | yes | policy source is FPL-on-disk path; behavior should match langchain-simple YAML row |
| `framework-hooks/langchain-governed-smoke` | passing | B | langchain | yes | yes | yes | no | no | yes | no | yes | yes | framework_autopatch | yes | smoke harness does not cover deny or defer outcomes; smoke harness does not exercise credential-brokered or shell-governed paths |
| `framework-hooks/langchain-simple` | passing | A | langchain | yes | yes | yes | yes | yes | yes | no | yes | yes | framework_autopatch | yes | the shared demo agent lives outside this corpus entry and should be localized in a later hardening pass |
| `framework-hooks/langgraph-fpl` | passing | A | langgraph | yes | yes | yes | yes | yes | yes | no | yes | yes | framework_autopatch | yes | policy source is FPL-on-disk; behavior should align with langgraph-single-agent YAML row |
| `framework-hooks/langgraph-multi-agent` | passing | A | langgraph | yes | yes | yes | no | no | no | no | yes | yes | framework_autopatch | yes | row covers LangGraph ToolNode delegation truth, but not a full graph-of-graphs orchestration runtime |
| `framework-hooks/langgraph-single-agent` | passing | A | langgraph | yes | yes | yes | yes | yes | yes | no | yes | yes | framework_autopatch | yes | full multi-agent LangGraph corpus coverage is not implemented yet |
| `mcp-servers/mcp-http-sse` | passing | A | mcp-http-sse | yes | yes | yes | no | no | yes | yes | yes | yes | mcp_gateway | yes | HTTP SSE row does not yet cover edge-auth, protocol-version strict mode, or session-expiry hardening |
| `mcp-servers/mcp-node-sdk` | passing | A | mcp-node-sdk | yes | yes | yes | no | yes | yes | yes | yes | yes | framework_autopatch | yes | this row covers Node MCP autopatch, not stdio or HTTP SSE server variants |
| `mcp-servers/mcp-stdio-wrap` | passing | B | mcp-stdio | yes | yes | yes | no | no | no | yes | yes | yes | mcp_gateway | yes | - |
| `policy-core/policy-roundtrip` | wip | C | faramesh-cli | no | no | yes | no | no | no | no | no | no | - | no | Policy validate / decompile / policy test only — not an agent stack; hook_truth + WAL replay parity not asserted for this row |
| `runtime-core/burst-rate-limits` | wip | C | faramesh-runtime | no | yes | no | no | no | no | no | no | no | - | no | SDK socket + proxy adapter burst rate-limit unit tests only — not corpus tier-A WAL replay + hook_truth |
| `runtime-core/defer-timeout-resume` | wip | C | faramesh-runtime | no | no | no | no | no | no | no | no | no | - | no | Go stress tests for late resolve, triage, and daemon wait-for-approval timeouts — not an agent hook_truth / WAL tier-A row |
| `runtime-core/linux-interception` | wip | C | faramesh-runtime | no | yes | yes | yes | yes | yes | no | no | no | - | no | `faramesh run` enforcement report matrix on Linux only; non-Linux hosts skip the harness (exit 0). Not a tier-A WAL + hook_truth agent row.; Some CI kernels may terminate the child under strict seccomp; harness tolerates selected exit codes when validating the report. |
| `runtime-core/socket-e2e-acceptance` | wip | C | faramesh-runtime | yes | yes | yes | yes | yes | no | no | no | no | - | no | Daemon + Unix socket JSON-RPC govern acceptance (demo.fpl); not a tier-A agent harness with WAL replay_parity + hook_truth contract; Previously ran only as a standalone release-gate job; now tracked in corpus matrix and corpus-harness alongside other runtime wip rows |
