# Run And Monitor

## Start runtime

```bash
faramesh up --policy policy.yaml
```

Advanced operator runtime path (optional):

```bash
faramesh serve --policy policy.yaml
```

Operator extension example (metrics enabled):

```bash
faramesh serve --policy policy.yaml --metrics-port 9108
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

Default approvals output is summary-first (queue/detail) with raw payloads available via `--json`.

## Observe-first commands

Use these to baseline before moving from shadow to enforce:

```bash
faramesh discover --cwd .
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

Default runtime-aware verification:

```bash
faramesh audit verify
```

Operator path for explicit WAL location (full chain validation):

```bash
faramesh audit verify /var/lib/faramesh/faramesh.wal
```

If the WAL file is unavailable, verify from SQLite store (this does not check chain links between records):

```bash
faramesh audit verify /var/lib/faramesh/faramesh.db
```

For programmatic use, `dpr.WAL.ReplayValidated` (package `internal/core/dpr`) applies the same chain rules as `faramesh audit verify` on a `.wal` file.

## Verify cryptographic integrity in audit views

Use `audit show` for per-record cryptographic status:

```bash
faramesh audit show <action-id>
```

Look for these fields in `dpr_record` output:

- `canonicalization_algorithm`
- `record_hash_valid`
- `signature_algorithm`
- `signature_valid`

`record_hash_valid=true` and `signature_valid=true` indicate the stored record hash and Ed25519 signature both verify for that action.

## Re-sign historical records (migration hardening)

When rolling out canonicalized Ed25519 signing on an existing deployment, run a dry-run first:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data
```

Apply signature backfill after review:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data --apply
```

Optional controls:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data --limit 5000 --only-missing
```

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

Operator note: reload policy after updates without restarting runtime:

```bash
faramesh policy reload
```

## See deny reason details

```bash
faramesh audit show <action-id>
faramesh audit trace --action-id <action-id>
faramesh explain <action-id>
faramesh explain approval <approval-id>
```

`audit show`, `audit trace`, and `explain` now print human-readable summaries first, with `--json` for raw payload views.

## Typical triage sequence

1. Keep `faramesh audit tail` open.
2. Capture `action_id` when an action is denied or deferred.
3. Run `faramesh audit show <action-id>` for quick evidence context.
4. Run `faramesh explain <action-id>` for full policy causality.
5. If deferred, resolve with `faramesh approvals approve|deny <approval-id>`.
6. Run `faramesh explain approval <approval-id>` to verify end-to-end approval linkage.
