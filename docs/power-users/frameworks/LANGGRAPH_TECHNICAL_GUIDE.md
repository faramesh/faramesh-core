# LangGraph Technical Guide

## Scope

This guide covers Faramesh governance behavior for LangGraph runtime usage in production.

## Integration model

LangGraph workloads are governed through runtime wrapping:

```bash
faramesh run -- python your_langgraph_app.py
```

## Patch and interception surface

From framework support mapping:

- Framework family: `LangGraph / LangChain`
- Primary patch point: `BaseTool.run()`

LangGraph tool execution that passes through this surface is governed before execution.

## Governance behavior

- deterministic pre-execution policy checks
- permit/deny/defer decision model
- tamper-evident decision evidence path

## Multi-agent and graph flow notes

LangGraph graph nodes and tool edges should be treated as policy-enforced execution units when they invoke tool runtime surfaces.

For MCP-backed tools inside graph flows, apply MCP boundary governance in addition to runtime wrapping.

## MCP boundary for graph-connected tools

- `faramesh mcp wrap -- <server>`
- or MCP HTTP gateway with hardening flags

MCP technical details:

- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)

## Validation commands

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

## Related docs

- Quick guide: [LANGGRAPH_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGGRAPH_QUICK_GUIDE.md)
- Product technical matrix: [FEATURES_TECHNICAL_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/FEATURES_TECHNICAL_REFERENCE.md)
