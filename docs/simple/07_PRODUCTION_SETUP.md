# Production Setup (Simple Checklist)

Use this as a minimal production checklist.

## Required

1. Dedicated policy file in version control
2. Dedicated data directory with backups
3. Service manager (systemd, container supervisor, etc.)
4. Monitoring on `/metrics`
5. Regular `audit verify` checks

## Recommended daemon command

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --socket /var/run/faramesh.sock \
  --metrics-port 9108 \
  --log-level info
```

## Optional PostgreSQL mirror

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --dpr-dsn "postgres://user:pass@host:5432/faramesh?sslmode=disable"
```

## Health and audit checks

```bash
curl -sS http://127.0.0.1:9108/metrics | head
faramesh audit verify /var/lib/faramesh/faramesh.db
```

## Identity hardening (SPIFFE/SPIRE)

If you run SPIRE, configure Faramesh to consume workload identity from the SPIFFE Workload API socket:

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --spiffe-socket unix:///run/spire/sockets/agent.sock
```

Then validate identity and trust material:

```bash
faramesh identity verify --spiffe spiffe://example.org/agent/faramesh
faramesh identity trust --domain example.org --bundle /etc/spiffe/bundle.pem
```

SPIRE/SPIFFE components handle CA issuance and SVID lifecycle. Faramesh consumes that identity to enforce policy and broker credentials.

## Observability backends

Use the same `/metrics` endpoint for multiple systems:

- Grafana: scrape with Prometheus/Alloy.
- Datadog: OpenMetrics scrape from `http://127.0.0.1:9108/metrics`.
- New Relic: Prometheus/OpenMetrics ingestion from `http://127.0.0.1:9108/metrics`.

## Horizon auth (optional)

```bash
faramesh auth login
faramesh auth status
```

Then start with sync:

```bash
faramesh serve --policy /etc/faramesh/policy.yaml --sync-horizon
```

## Also read

- `../MVP_PRODUCTION_RUNBOOK.md`
