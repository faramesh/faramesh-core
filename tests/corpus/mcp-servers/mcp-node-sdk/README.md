# mcp-node-sdk

This corpus entry exercises the Node MCP autopatch real-stack harness.

Why it exists:

- Proves protocol-level governance stays active for MCP tool calls in Node
- Verifies permit, default deny, defer, and fail-closed behavior in the Node autopatch path
- Supplies the first MCP-oriented compatibility row for the release matrix

Current harness:

- Delegates to `tests/node_autopatch_real_stack.sh`

Known limitations:

- This row covers Node MCP autopatch, not stdio/HTTP SSE server variants yet
- Static project discovery is not part of the harness itself and is represented from the declared expected surfaces
