# MCP Interception and Governance (Quick Guide)

This guide is for teams that want to run MCP governance fast in real environments.

If you want the full protocol details, edge-case behavior, and hardening internals, use the power-user spec:

- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)

## What This Gives You

Faramesh sits between your agent and your MCP server.

- Every `tools/call` is governed by policy.
- Non-tool MCP methods pass through.
- Every decision is logged.

You can run this in two ways:

1. `faramesh mcp wrap -- <server>` for stdio MCP servers
2. `faramesh serve --mcp-proxy-port ... --mcp-target ...` for HTTP MCP servers

## 60-Second Start (stdio MCP)

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

Point your MCP client to `faramesh mcp wrap -- ...` instead of directly to the server.

## 60-Second Start (HTTP MCP)

```bash
faramesh serve \
  --policy examples/mcp-server.fpl \
  --mcp-proxy-port 19092 \
  --mcp-target http://127.0.0.1:8080
```

Then point your MCP client to `http://127.0.0.1:19092`.

## Fast Adoption by Stack

### LangChain / LangGraph / Deep Agents

Keep your normal agent entrypoint, and put Faramesh on the MCP boundary.

1. Run the agent with Faramesh:

```bash
faramesh run -- python your_agent.py
```

2. If your agent calls MCP tools, run those MCP servers through `faramesh mcp wrap -- ...` or the MCP HTTP gateway.

### MCP Clients (Claude Code, Cursor, other MCP agents)

Replace direct MCP server commands with Faramesh-wrapped commands:

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

## Production Start (Recommended)

```bash
faramesh serve \
  --policy policy.yaml \
  --mcp-proxy-port 19092 \
  --mcp-target http://127.0.0.1:8080 \
  --mcp-allowed-origins https://app.example.com \
  --mcp-edge-auth-mode bearer \
  --mcp-edge-auth-bearer-token "$FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN" \
  --mcp-protocol-version-mode strict \
  --mcp-protocol-version 2025-06-18 \
  --mcp-session-ttl 30m \
  --mcp-session-idle-timeout 10m \
  --mcp-sse-replay-enabled \
  --mcp-sse-replay-max-events 256 \
  --mcp-sse-replay-max-age 10m
```

## What Happens to Requests

For `tools/call`:

- `PERMIT`: forwarded to MCP server
- `DENY`: blocked with JSON-RPC error
- `DEFER`: returned as pending approval

For other MCP messages:

- forwarded to MCP server
- one-way messages follow MCP one-way semantics

## Quick Validation

```bash
go test ./internal/adapter/mcp ./cmd/faramesh ./internal/daemon
go test ./...
```

## Fast Troubleshooting

1. If everything is blocked, check policy and auth mode first.
2. If browser clients fail, check `--mcp-allowed-origins`.
3. If strict protocol mode fails, verify `MCP-Protocol-Version` header value.
4. If replay is expected but not happening, confirm `--mcp-sse-replay-enabled` and session continuity (`Mcp-Session-Id`).

## When to Use the Power-User Spec

Use the advanced spec if you need:

- exact JSON-RPC and transport behavior
- detailed edge auth mode behavior
- strict protocol-version request/response rules
- session TTL/idle lifecycle internals
- SSE replay behavior and cache boundaries
- implementation/test breakdown by file

Power-user spec:

- [MCP_INTERCEPTION_GOVERNANCE_SPEC.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md)
