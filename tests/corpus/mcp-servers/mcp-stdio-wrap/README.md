# mcp-stdio-wrap

This corpus entry exercises the real `faramesh mcp wrap` stdio path against a local stdio MCP server.

Why it exists:

- Proves `tools/call` interception in stdio mode
- Verifies permit, deny, defer, local defer status/resolution continuity, non-tool passthrough, unsolicited upstream notification forwarding, audit verification, and replay parity
- Adds a truthful MCP stdio row to the compatibility lab

Current harness:

- Delegates to `tests/mcp_stdio_wrap_harness.sh`

Known limitations:

- The stdio wrap row covers defer status/resolution continuity, but does not yet resume the original upstream execution after approval
