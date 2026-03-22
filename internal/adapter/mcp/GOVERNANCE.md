# MCP adapter — governance posture

## What is governed today

- **HTTP gateway** (`internal/adapter/mcp/gateway.go`): JSON-RPC **`tools/call`** (and batch) evaluated through **`core.Pipeline`** before upstream; post-scan hooks on MCP-shaped responses where configured.
- **Stdio gateway** + **`faramesh mcp wrap`**: line-oriented JSON-RPC (including batches) through **`ProcessStdioLine`**.

## Trust boundary

MCP governance applies to **traffic that flows through the gateway**. It does **not** constrain:

- A sibling process that talks to the same upstream MCP server **without** the gateway.
- Raw HTTP/stdio from the agent runtime that bypasses the configured MCP transport.

Pair with **`ENFORCEMENT_STACK_AND_TRUST.md`** (network + broker + optional kernel layers) for host-level posture.

## State-of-the-art backlog

- Full **capabilities / version** matrix in CI.
- **Elicitation** and **sampling** governance (deny/defer with DPR).
- **Multi-upstream** fan-out rules (which server, which tool namespace).

See **`docs/dev/TODO.md`** → *MCP protocol parity*.
