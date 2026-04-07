# Faramesh Features (Power-User Technical Reference)

This is the complete technical map for major Faramesh product features.

Use this when you need architecture internals, control surfaces, and operational nuance.

For simple usage, use:

- `../guides/FEATURES_QUICK_GUIDE.md`

## Coverage Policy

Every major user-facing feature has two tracks:

1. Quick usage track (simple language)
2. Power-user track (deep technical detail)

This document is the power-user umbrella for the whole product.

## Product-Wide Feature Matrix

| Feature Domain | Quick Usage Doc | Power/Technical Doc |
|---|---|---|
| Install and onboarding | `../simple/01_INSTALL.md`, `../simple/00_START_HERE.md` | `../README.md` |
| Setup lifecycle automation | `../simple/00_START_HERE.md` | `../README.md` |
| Agent governance runtime | `../simple/02_QUICKSTART.md` | `../README.md` |
| LangChain runtime governance | `../guides/frameworks/LANGCHAIN_QUICK_GUIDE.md` | `frameworks/LANGCHAIN_TECHNICAL_GUIDE.md` |
| LangGraph runtime governance | `../guides/frameworks/LANGGRAPH_QUICK_GUIDE.md` | `frameworks/LANGGRAPH_TECHNICAL_GUIDE.md` |
| Deep Agents runtime governance | `../guides/frameworks/DEEP_AGENTS_QUICK_GUIDE.md` | `frameworks/DEEP_AGENTS_TECHNICAL_GUIDE.md` |
| Policy authoring (FPL) | `../simple/03_POLICY_SIMPLE.md` | `../fpl/POLICY_AUTHORING_REFERENCE.md`, `../fpl/LANGUAGE_REFERENCE.md` |
| Runtime monitoring and DPR | `../simple/04_RUN_AND_MONITOR.md` | `../README.md` |
| Human approvals (DEFER flow) | `../simple/05_APPROVALS.md` | `../README.md` |
| Adapter usage (general) | `../simple/06_ADAPTERS.md` | `../README.md` |
| MCP governance | `../guides/MCP_INTERCEPTION_GOVERNANCE_PLAN.md` | `mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md` |
| Production setup controls | `../simple/07_PRODUCTION_SETUP.md` | `../README.md` |
| Troubleshooting | `../simple/08_TROUBLESHOOTING.md` | `../README.md` |
| Network hardening rollout | `../guides/NETWORK_HARDENING_CANARY_RUNBOOK.md` | `../guides/NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md` |
| Chain exfil hardening | `../guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md` | `../guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md` |
| Credential broker | `../guides/FEATURES_QUICK_GUIDE.md` | `../README.md` |
| SPIFFE workload identity | `../guides/FEATURES_QUICK_GUIDE.md` | `../README.md` |
| Observability and metrics | `../guides/FEATURES_QUICK_GUIDE.md` | `../README.md` |
| SDK surfaces (Python/Node) | `../guides/FEATURES_QUICK_GUIDE.md` | `../README.md`, `../../sdk/python/README.md`, `../../sdk/node/README.md` |

## Technical Breakdown by Feature

### 1. Governance Runtime and Decision Pipeline

- Deterministic policy evaluation is executed before tool dispatch.
- Decision effects include permit/deny/defer flows.
- Durable decision recording (WAL/DPR) is part of governance assurance.

Source anchors:

- `../README.md` (architecture and runtime sections)
- `../../internal/core/`

### 2. Policy Language (FPL)

- FPL is the canonical policy authoring language for Faramesh.
- FPL references include syntax, authoring patterns, and reliability reporting.

Source anchors:

- `../fpl/README.md`
- `../fpl/LANGUAGE_REFERENCE.md`
- `../fpl/POLICY_AUTHORING_REFERENCE.md`
- `../fpl/BENCHMARK_RELIABILITY_REPORTING.md`

### 3. Adapter and Integration Surfaces

Primary integration surfaces are exposed through runtime commands and adapter pathways.

- Runtime wrapping path via `faramesh run -- <cmd>`.
- MCP-specific wrapper and HTTP gateway paths.
- Additional adapter details in simple adapter docs and architecture docs.

Source anchors:

- `../simple/06_ADAPTERS.md`
- `mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md`

### 3a. Framework-Specific Runtime Guides

- LangChain technical guide: `frameworks/LANGCHAIN_TECHNICAL_GUIDE.md`
- LangGraph technical guide: `frameworks/LANGGRAPH_TECHNICAL_GUIDE.md`
- Deep Agents technical guide: `frameworks/DEEP_AGENTS_TECHNICAL_GUIDE.md`

### 4. MCP Technical Surface

- Full JSON-RPC handling model
- Streamable HTTP considerations
- one-way semantics for notification/response paths
- session lifecycle and replay behavior under hardened mode
- edge auth and protocol-version enforcement

Source anchor:

- `mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md`

### 5. Security and Hardening Domains

#### Network hardening

- Progressive control strategy with canary and enforce operational tracks.

Source anchors:

- `../guides/NETWORK_HARDENING_CANARY_RUNBOOK.md`
- `../guides/NETWORK_HARDENING_PROGRESSIVE_ENFORCE_RUNBOOK.md`

#### Chain exfil hardening

- Multi-stage hardening process for exfil patterns across action chains.

Source anchor:

- `../guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md`

### 6. Credential and Identity Controls

- Credential broker boundary separates secret handling from agent runtime.
- SPIFFE workload identity can be integrated for identity-aware controls.

Source anchors:

- `../README.md`

### 7. Operations, Metrics, and Validation

- Metrics endpoint is available via `--metrics-port`.
- Validation baseline includes focused and full test execution.

Suggested validation commands:

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

