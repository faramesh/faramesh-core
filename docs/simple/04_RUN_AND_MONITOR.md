# Run And Monitor

## Start runtime

```bash
faramesh up --policy policy.yaml
```

Advanced operator runtime path (optional):

```bash
faramesh serve --policy policy.yaml
```

Advanced flags for explicit infrastructure control:

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

## Resolve deferred actions

```bash
faramesh approvals
faramesh approvals watch
faramesh approvals show <approval-id>
faramesh approvals history --agent <agent-id>
faramesh approvals approve <approval-id>
faramesh approvals deny <approval-id>
```

## Observe-first commands

Use these to baseline before moving from shadow to enforce:

```bash
faramesh discover --source ./
faramesh attach --cwd . --observation-window 30s
faramesh coverage
faramesh gaps
faramesh suggest
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
faramesh policy reload
```

Advanced operator path when managing a non-default daemon data directory:

```bash
faramesh policy reload --data-dir /var/lib/faramesh
```

## See deny reason details

```bash
faramesh audit show <action-id>
faramesh audit trace --action-id <action-id>
faramesh explain <action-id>
faramesh explain approval <approval-id>
```

## Typical triage sequence

1. Keep `faramesh audit tail` open.
2. Capture `action_id` when an action is denied or deferred.
3. Run `faramesh audit show <action-id>` for quick evidence context.
4. Run `faramesh explain <action-id>` for full policy causality.
5. If deferred, resolve with `faramesh approvals approve|deny <approval-id>`.
6. Run `faramesh explain approval <approval-id>` to verify end-to-end approval linkage.
