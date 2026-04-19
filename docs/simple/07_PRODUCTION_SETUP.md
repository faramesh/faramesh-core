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
  --dpr-hmac-key <DPR_HMAC_KEY> \
  --metrics-port 9108 \
  --log-level info
```

Set a stable `--dpr-hmac-key` from your secret manager or service config. If you omit it, the daemon persists a generated key under the data directory (`faramesh.hmac.key`). See `docs/guides/DPR_HMAC_KEY.md`. Configure `--standing-admin-token` (or reuse `--policy-admin-token`) so `faramesh agent standing-grant` APIs are authenticated.

Recommended rollout pattern for packs:

```bash
faramesh pack status faramesh/<pack>
faramesh pack shadow faramesh/<pack>
# monitor coverage / audit outcomes
faramesh pack enforce faramesh/<pack>
```

## Optional PostgreSQL mirror

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --dpr-dsn "postgres://user:pass@host:5432/faramesh?sslmode=disable"
```

## Hard Secret Boundary Setup (Vault + Broker)

Use this flow when you want keys outside agent process memory by default.

### Local Vault provisioned by Faramesh (command-native)

```bash
faramesh credential enable --policy /etc/faramesh/policy.fpl

faramesh up --policy /etc/faramesh/policy.fpl

# Run agent with ambient key stripping
faramesh run --broker --agent-id payments-prod -- python your_agent.py
```

Advanced operator path (optional): add backend and provider mappings explicitly when your environment requires manual Vault routing.

### External Vault

```bash
faramesh credential enable \
  --policy /etc/faramesh/policy.fpl \
  --backend vault \
  --vault-addr https://vault.company.internal:8200 \
  --vault-token "$VAULT_TOKEN"

faramesh up --policy /etc/faramesh/policy.fpl
```

Operational helpers:

```bash
faramesh credential status
faramesh credential vault status
faramesh credential vault down
```

## Health and audit checks

```bash
faramesh status
faramesh approvals history --agent payments-prod
faramesh explain agent payments-prod
faramesh explain run <run-or-session-id>
faramesh audit verify /var/lib/faramesh/faramesh.wal
faramesh audit show <action-id>
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
faramesh identity status
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
