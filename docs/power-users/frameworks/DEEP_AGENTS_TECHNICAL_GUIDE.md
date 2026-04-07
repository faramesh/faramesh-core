# Deep Agents Technical Guide

## Scope

This guide covers Faramesh governance behavior for Deep Agents runtime usage.

## Integration model

Runtime command:

```bash
faramesh run -- python -m deep_agents.main
```

## Interception surfaces

Framework support mapping includes:

- Deep Agents: `LangGraph dispatch + AgentMiddleware`

This indicates governance coverage for deep-agent execution paths through graph dispatch and middleware surfaces.

## Governance properties

- pre-execution policy enforcement
- permit/deny/defer decision path
- centralized decision stream and audit evidence

## Delegation and sub-agent behavior

Deep agent flows with delegation should still run through governed execution boundaries. Keep supervisor policies explicit and bounded for delegated actions.

## MCP interoperability

If Deep Agents workloads use MCP tools, use MCP boundary governance:

- `faramesh mcp wrap -- <server>`
- or HTTP MCP gateway

MCP full technical details:

- `../mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md`

## Validation commands

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

## Related docs

- Quick guide: `../../guides/frameworks/DEEP_AGENTS_QUICK_GUIDE.md`
- Product technical matrix: `../FEATURES_TECHNICAL_REFERENCE.md`
