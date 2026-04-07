# Faramesh Features (Power-User Technical Reference)

This is the complete technical map for major Faramesh product features.

Use this when you need architecture internals, control surfaces, and operational nuance.

For simple usage, use:

- [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md)

## Coverage Policy

Every major user-facing feature has two tracks:

1. Quick usage track (simple language)
2. Power-user track (deep technical detail)

This document is the power-user umbrella for the whole product.

## Product-Wide Feature Matrix

| Feature Domain | Quick Usage Doc | Power/Technical Doc |
|---|---|---|
| Install and onboarding | [01_INSTALL.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/01_INSTALL.md), [00_START_HERE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/00_START_HERE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Setup lifecycle automation | [00_START_HERE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/00_START_HERE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Agent governance runtime | [02_QUICKSTART.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/02_QUICKSTART.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| LangChain runtime governance | [LANGCHAIN_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGCHAIN_QUICK_GUIDE.md) | [LANGCHAIN_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/LANGCHAIN_TECHNICAL_GUIDE.md) |
| LangGraph runtime governance | [LANGGRAPH_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGGRAPH_QUICK_GUIDE.md) | [LANGGRAPH_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/LANGGRAPH_TECHNICAL_GUIDE.md) |
| Deep Agents runtime governance | [DEEP_AGENTS_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/DEEP_AGENTS_QUICK_GUIDE.md) | [DEEP_AGENTS_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/DEEP_AGENTS_TECHNICAL_GUIDE.md) |
| Policy authoring (FPL) | [03_POLICY_SIMPLE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/03_POLICY_SIMPLE.md) | [POLICY_AUTHORING_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/POLICY_AUTHORING_REFERENCE.md), [LANGUAGE_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/LANGUAGE_REFERENCE.md) |
| Runtime monitoring and DPR | [04_RUN_AND_MONITOR.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/04_RUN_AND_MONITOR.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Human approvals (DEFER flow) | [05_APPROVALS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/05_APPROVALS.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Adapter usage (general) | [06_ADAPTERS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/06_ADAPTERS.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| MCP governance | [MCP_INTERCEPTION_GOVERNANCE_PLAN.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/MCP_INTERCEPTION_GOVERNANCE_PLAN.md) | [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md) |
| Production setup controls | [07_PRODUCTION_SETUP.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/07_PRODUCTION_SETUP.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Troubleshooting | [08_TROUBLESHOOTING.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/08_TROUBLESHOOTING.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Network hardening rollout | [NETWORK_HARDENING_CANARY_RUNBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/NETWORK_HARDENING_CANARY_RUNBOOK.md) | [NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md) |
| Chain exfil hardening | [CHAIN_EXFIL_HARDENING_PLAYBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md) | [CHAIN_EXFIL_HARDENING_PLAYBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md) |
| Credential broker | [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| SPIFFE workload identity | [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Observability and metrics | [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| SDK surfaces (Python/Node) | [FEATURES_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/FEATURES_QUICK_GUIDE.md) | [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md), [README.md](https://github.com/faramesh/faramesh-core/blob/main/sdk/python/README.md), [README.md](https://github.com/faramesh/faramesh-core/blob/main/sdk/node/README.md) |

## Technical Breakdown by Feature

### 1. Governance Runtime and Decision Pipeline

- Deterministic policy evaluation is executed before tool dispatch.
- Decision effects include permit/deny/defer flows.
- Durable decision recording (WAL/DPR) is part of governance assurance.

Source anchors:

- [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) (architecture and runtime sections)
- [internal/core](https://github.com/faramesh/faramesh-core/tree/main/internal/core)

### 2. Policy Language (FPL)

- FPL is the canonical policy authoring language for Faramesh.
- FPL references include syntax, authoring patterns, and reliability reporting.

Source anchors:

- [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/README.md)
- [LANGUAGE_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/LANGUAGE_REFERENCE.md)
- [POLICY_AUTHORING_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/POLICY_AUTHORING_REFERENCE.md)
- [BENCHMARK_RELIABILITY_REPORTING.md](https://github.com/faramesh/faramesh-core/blob/main/docs/fpl/BENCHMARK_RELIABILITY_REPORTING.md)

### 3. Adapter and Integration Surfaces

Primary integration surfaces are exposed through runtime commands and adapter pathways.

- Runtime wrapping path via `faramesh run -- <cmd>`.
- MCP-specific wrapper and HTTP gateway paths.
- Additional adapter details in simple adapter docs and architecture docs.

Source anchors:

- [06_ADAPTERS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/06_ADAPTERS.md)
- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)

### 3a. Framework-Specific Runtime Guides

- LangChain technical guide: [LANGCHAIN_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/LANGCHAIN_TECHNICAL_GUIDE.md)
- LangGraph technical guide: [LANGGRAPH_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/LANGGRAPH_TECHNICAL_GUIDE.md)
- Deep Agents technical guide: [DEEP_AGENTS_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/DEEP_AGENTS_TECHNICAL_GUIDE.md)

### 4. MCP Technical Surface

- Full JSON-RPC handling model
- Streamable HTTP considerations
- one-way semantics for notification/response paths
- session lifecycle and replay behavior under hardened mode
- edge auth and protocol-version enforcement

Source anchor:

- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)

### 5. Security and Hardening Domains

#### Network hardening

- Progressive control strategy with canary and enforce operational tracks.

Source anchors:

- [NETWORK_HARDENING_CANARY_RUNBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/NETWORK_HARDENING_CANARY_RUNBOOK.md)
- [NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md)

#### Chain exfil hardening

- Multi-stage hardening process for exfil patterns across action chains.

Source anchor:

- [CHAIN_EXFIL_HARDENING_PLAYBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md)

### 6. Credential and Identity Controls

- Credential broker boundary separates secret handling from agent runtime.
- SPIFFE workload identity can be integrated for identity-aware controls.

Source anchors:

- [README.md](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md)

### 7. Operations, Metrics, and Validation

- Metrics endpoint is available via `--metrics-port`.
- Validation baseline includes focused and full test execution.

Suggested validation commands:

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

