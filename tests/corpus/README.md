# Faramesh Agent Corpus

This directory is the bootstrap compatibility lab for Faramesh.

Current scope:

- It is intentionally seeded only with entries backed by real harnesses that already exist in `tests/`.
- Each entry declares expected governance outcomes in `expected.json`.
- The coverage matrix is generated from these corpus entries so release gating can start from truthful data and expand over time.

Current bootstrap entries:

| Entry | Status | Harness |
|-------|--------|---------|
| `framework-hooks/langchain-governed-smoke` | passing | `tests/langchain_single_agent_governed.sh` |
| `framework-hooks/langchain-simple` | passing | `tests/langchain_single_agent_real_stack.sh` |
| `framework-hooks/langchain-fpl` | passing | `tests/langchain_single_agent_real_stack_fpl.sh` |
| `framework-hooks/deepagents-governed` | passing | `tests/deepagents_real_stack.sh` |
| `framework-hooks/langgraph-multi-agent` | passing | `tests/langgraph_multi_agent_real_stack.sh` |
| `framework-hooks/langgraph-single-agent` | passing | `tests/langgraph_single_agent_real_stack.sh` |
| `framework-hooks/langgraph-fpl` | passing | `tests/langgraph_single_agent_real_stack_fpl.sh` |
| `mcp-servers/mcp-stdio-wrap` | passing | `tests/mcp_stdio_wrap_harness.sh` |
| `mcp-servers/mcp-http-sse` | passing | `tests/mcp_http_sse_real_stack.sh` |
| `mcp-servers/mcp-node-sdk` | passing | `tests/node_autopatch_real_stack.sh` |
| `policy-core/policy-roundtrip` | wip | `tests/policy_roundtrip_harness.sh` |
| `runtime-core/defer-timeout-resume` | wip | `tests/defer_timeout_resume_stress_harness.sh` |
| `runtime-core/burst-rate-limits` | wip | `tests/burst_rate_limit_harness.sh` |
| `runtime-core/linux-interception` | wip | `tests/linux_interception_matrix_harness.sh` |
| `runtime-core/socket-e2e-acceptance` | wip | `tests/socket_e2e_acceptance.sh` |

Matrix workflow:

- Validate `expected.json` contract (replay parity, `hook_truth`, required fields) with `make corpus-contract` (also runs at the start of `make corpus-check`)
- Regenerate artifacts locally with `make corpus-matrix`
- Verify the committed artifacts are fresh with `make corpus-check`
- Run one corpus row locally with `make corpus-run ENTRY=tests/corpus/framework-hooks/langchain-governed-smoke`
- **PR CI** (`.github/workflows/ci.yml` and monorepo `faramesh-core-ci.yml`): `corpus-matrix` uploads matrix artifacts; **corpus-harness** matrix runs agent stacks, MCP rows, `linux-interception`, `defer-timeout-resume`, `burst-rate-limits`, `policy-roundtrip`, **`socket-e2e-acceptance`**. Standalone burst/defer jobs were **removed** — same `go test` lanes run only via corpus wrappers.
- **Release gate** (`release-gate.yml` and monorepo `faramesh-core-release-gate.yml`): same **`corpus-matrix`** + **`corpus-harness`** matrix (including **`socket-e2e-acceptance`**; the former standalone socket job was folded into this matrix).
- **Version tags** (`release.yml`, on `v*.*.*`): **`corpus-harness`** matrix matches **PR CI** (`ci.yml`) — full framework, MCP, runtime **wip**, `policy-roundtrip`, and **`socket-e2e-acceptance`** rows.

Conventions:

- `README.md`: what the entry covers and what is still missing
- `expected.json`: expected tool outcomes and enforcement surfaces
- `test.sh`: stable wrapper that delegates to the real harness

Future entries should only be added after they have a real runnable harness.
