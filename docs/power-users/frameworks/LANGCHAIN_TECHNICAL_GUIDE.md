# LangChain Technical Guide

## Scope

This guide covers Faramesh governance behavior for LangChain runtime usage in production.

## Integration model

LangChain governance is applied through Faramesh runtime wrapping:

```bash
faramesh run -- python your_langchain_agent.py
```

## Patch and interception surface

From repo-level framework support mapping:

- Framework family: `LangGraph / LangChain`
- Primary patch point: `BaseTool.run()`

This means tool execution pathways routed through LangChain tool runtime are intercepted for governance checks before execution.

## Governance behavior

- Pre-execution policy evaluation on tool actions
- Decision effects: permit/deny/defer
- Audit-chain evidence for decisions

## MCP cross-boundary behavior

If a LangChain app uses MCP tools, use MCP boundary governance as well:

- stdio boundary: `faramesh mcp wrap -- <server>`
- HTTP boundary: `faramesh serve --mcp-proxy-port ... --mcp-target ...`

Detailed MCP semantics:

- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)

## Operational controls

Recommended baseline for production:

1. deny-by-default policy for sensitive tools
2. live decision monitoring (`faramesh audit tail`)
3. full test/verification before rollout

## Validation commands

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

## Related docs

- Quick guide: [LANGCHAIN_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGCHAIN_QUICK_GUIDE.md)
- Product technical matrix: [FEATURES_TECHNICAL_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/FEATURES_TECHNICAL_REFERENCE.md)
