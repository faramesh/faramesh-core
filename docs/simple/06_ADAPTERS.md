# Adapters (Simple)

Faramesh can receive tool calls through different adapters.

## SDK adapter (Unix socket)

- Enabled by default in `faramesh serve`
- Default socket: `/tmp/faramesh.sock`

Start with custom socket:

```bash
faramesh serve --policy policy.yaml --socket /var/run/faramesh.sock
```

## HTTP proxy adapter

Start:

```bash
faramesh serve --policy policy.yaml --proxy-port 19090
```

Authorize endpoint:

- `POST /v1/authorize`

## MCP HTTP gateway

Start:

```bash
faramesh serve \
  --policy policy.yaml \
  --mcp-proxy-port 19092 \
  --mcp-target http://127.0.0.1:8080
```

- Intercepts `tools/call`
- For non-tool calls, forwards to target MCP server

## MCP stdio wrapper

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

## gRPC daemon adapter

Start:

```bash
faramesh serve --policy policy.yaml --grpc-port 19091
```

Notes:

- The daemon gRPC contract is defined in `api/v1/faramesh.proto`.
- The current in-repo client keeps JSON codec compatibility for local usage.

## eBPF adapter

- Linux-only scaffold for future syscall-level interception
- Not available on macOS/Windows
- Current build does not load BPF LSM programs; fallback behavior is expected
