# Run And Monitor

## Start daemon

```bash
faramesh serve --policy policy.yaml
```

Useful flags:

- `--data-dir`: where WAL/DB files are stored
- `--socket`: Unix socket path for SDK adapter
- `--log-level`: debug|info|warn|error
- `--metrics-port`: exposes `/metrics`
- `--proxy-port`: starts HTTP proxy adapter
- `--grpc-port`: starts gRPC daemon adapter
- `--mcp-proxy-port` and `--mcp-target`: starts MCP HTTP gateway

Example:

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --socket /var/run/faramesh.sock \
  --metrics-port 9108
```

## Stream live decisions

```bash
faramesh audit tail
```

Filter by agent:

```bash
faramesh audit tail --agent my-agent
```

## Verify chain integrity

```bash
faramesh audit verify /var/lib/faramesh/faramesh.db
```

## Reload policy without restart

```bash
faramesh policy reload --data-dir /var/lib/faramesh
```

## See deny reason details

```bash
faramesh explain --last-deny --db /var/lib/faramesh/faramesh.db --policy /etc/faramesh/policy.yaml
```
