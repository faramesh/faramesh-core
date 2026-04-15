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

## Observe-first commands

Use these to baseline before moving from shadow to enforce:

```bash
faramesh discover --source ./
faramesh attach --agent-id my-agent --cmd "python agent.py"
faramesh coverage --agent-id my-agent
faramesh gaps --agent-id my-agent
faramesh suggest --agent-id my-agent
```

If you installed a policy pack, inspect and switch mode directly:

```bash
faramesh pack status faramesh/<pack>
faramesh pack shadow faramesh/<pack>
faramesh pack enforce faramesh/<pack>
```

## Verify chain integrity

For full chain validation (genesis markers, hash chains, and CRC per agent), use the WAL file:

```bash
faramesh audit verify /var/lib/faramesh/faramesh.wal
```

If the WAL file is unavailable, you can verify per-record hashes from the SQLite store (this does not check chain links between records):

```bash
faramesh audit verify /var/lib/faramesh/faramesh.db
```

For programmatic use, `dpr.WAL.ReplayValidated` (package `internal/core/dpr`) applies the same chain rules as `faramesh audit verify` on a `.wal` file.

## Export metrics to Datadog, Grafana, and New Relic

Faramesh exposes Prometheus-compatible metrics at `/metrics` when `--metrics-port` is enabled.

- Grafana: scrape `http://<host>:<metrics-port>/metrics` with Prometheus or Grafana Alloy.
- Datadog: configure OpenMetrics scraping for `http://<host>:<metrics-port>/metrics`.
- New Relic: use Prometheus/OpenMetrics integration to scrape `http://<host>:<metrics-port>/metrics`.

This keeps one telemetry endpoint while supporting multiple backends.

## Reload policy without restart

```bash
faramesh policy reload --data-dir /var/lib/faramesh
```

## See deny reason details

```bash
faramesh explain --last-deny --db /var/lib/faramesh/faramesh.db --policy /etc/faramesh/policy.yaml
```
