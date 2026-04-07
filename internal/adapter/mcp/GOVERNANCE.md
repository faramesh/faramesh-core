# MCP adapter — governance posture

## What is governed today

- **HTTP gateway** (`internal/adapter/mcp/gateway.go`): JSON-RPC **`tools/call`** (and batch) evaluated through **`core.Pipeline`** before upstream; post-scan hooks on MCP-shaped responses where configured.
- **Stdio gateway** + **`faramesh mcp wrap`**: line-oriented JSON-RPC (including batches) through **`ProcessStdioLine`**.

## Trust boundary

MCP governance applies to **traffic that flows through the gateway**. It does **not** constrain:

- A sibling process that talks to the same upstream MCP server **without** the gateway.
- Raw HTTP/stdio from the agent runtime that bypasses the configured MCP transport.

Pair with public deployment docs and the repository **`README.md`** enforcement sections for host-level posture details.

## Where to go next

- Quick usage guide:
	- **`docs/guides/MCP_INTERCEPTION_GOVERNANCE_PLAN.md`**
- Full technical reference:
	- **`docs/power-users/mcp/MCP_INTERCEPTION_GOVERNANCE_SPEC.md`**

This file is a short posture summary only.
