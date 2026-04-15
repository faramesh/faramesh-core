# mcp-http-sse

This corpus entry exercises the Faramesh MCP HTTP gateway against a local upstream SSE server.

Why it exists:

- Proves governed `tools/call` interception in HTTP mode
- Verifies deny blocks upstream forwarding
- Verifies SSE replay behavior with `Last-Event-ID`
- Verifies audit-chain integrity and WAL replay parity after governed MCP HTTP traffic

Current harness:

- Delegates to `tests/mcp_http_sse_real_stack.sh`
