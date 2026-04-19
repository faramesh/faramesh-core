# Adapters (Simple)

Most users do not need adapter internals.

Normal path:

```bash
faramesh up --policy policy.yaml
faramesh run --broker -- python your_agent.py
```

Faramesh chooses the right runtime wiring automatically for common local usage.

## Operator adapter modes (advanced)

Use these only when you are running custom infrastructure or integration tests.

### SDK adapter (Unix socket)

- Enabled automatically in normal runtime lifecycle commands.
- Override socket only for advanced/operator scenarios.

### HTTP proxy adapter

```bash
faramesh serve --policy policy.yaml --proxy-port 19090
```

### MCP HTTP gateway

```bash
faramesh serve \
  --policy policy.yaml \
  --mcp-proxy-port 19092 \
  --mcp-target http://127.0.0.1:8080
```

### MCP stdio wrapper

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

### gRPC daemon adapter

```bash
faramesh serve --policy policy.yaml --grpc-port 19091
```

### eBPF adapter

- Linux-only scaffold for future syscall-level interception.
- Not available on macOS/Windows.
- Current build does not load BPF LSM programs; fallback behavior is expected.

For protocol-level endpoint details and deep adapter contracts, use the power-user docs.