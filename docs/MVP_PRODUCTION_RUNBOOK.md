# Faramesh Core Minimal MVP Production Runbook

This runbook is for a fast, real deployment you can run today.
It is intentionally scoped to a minimal production profile:

- Single region
- Single tenant or trusted internal agents
- Local WAL + SQLite DPR store (optional PostgreSQL mirror)
- SDK socket entrypoint plus optional proxy/gRPC/MCP adapters

## 1) Build and Install

```bash
git clone https://github.com/faramesh/faramesh-core.git
cd faramesh-core
go build -o faramesh ./cmd/faramesh
sudo install -m 0755 faramesh /usr/local/bin/faramesh
```

## 2) Create Runtime Directories

```bash
sudo mkdir -p /etc/faramesh
sudo mkdir -p /var/lib/faramesh
sudo mkdir -p /var/log/faramesh
```

## 3) Create Baseline Policy

Create `/etc/faramesh/policy.yaml`:

```yaml
faramesh-version: "1.0"
agent-id: "prod-agent"
default_effect: "deny"

budget:
  max_calls: 50000
  session_usd: 50
  daily_usd: 500
  on_exceed: deny

tools:
  stripe/refund:
    reversibility: reversible
    blast_radius: medium
    cost_usd: 0.02
  shell/run:
    reversibility: irreversible
    blast_radius: high

rules:
  - id: deny-destructive-shell
    match:
      tool: shell/run
      when: 'args["cmd"] matches "rm\\s+-[rf]"'
    effect: deny
    reason: destructive shell command blocked
    reason_code: DESTRUCTIVE_SHELL_COMMAND

  - id: defer-high-value-refund
    match:
      tool: stripe/refund
      when: 'args["amount"] > 1000'
    effect: defer
    reason: high value refund requires approval
    reason_code: HIGH_VALUE_REFUND

  - id: allow-safe-defaults
    match:
      tool: "*"
      when: "true"
    effect: permit
    reason: default permit for approved tool surface
    reason_code: SAFE_DEFAULT
```

Validate policy before daemon startup:

```bash
faramesh policy validate /etc/faramesh/policy.yaml
```

## 4) Start the Daemon (MVP Profile)

```bash
faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --socket /var/run/faramesh.sock \
  --log-level info \
  --metrics-port 9108
```

Optional adapters:

```bash
# Add HTTP proxy adapter
--proxy-port 19090

# Add gRPC adapter
--grpc-port 19091

# Add MCP HTTP gateway
--mcp-proxy-port 19092 --mcp-target http://127.0.0.1:8080
```

Optional PostgreSQL mirror:

```bash
--dpr-dsn "postgres://user:pass@127.0.0.1:5432/faramesh?sslmode=disable"
```

## 5) Verify It Is Live

In another terminal:

```bash
faramesh audit tail
```

Generate traffic:

```bash
faramesh demo
```

Verify DPR chain integrity:

```bash
faramesh audit verify /var/lib/faramesh/faramesh.db
```

Explain a DENY:

```bash
faramesh explain --last-deny --db /var/lib/faramesh/faramesh.db --policy /etc/faramesh/policy.yaml
```

## 6) Hot Reload Policy

Update `/etc/faramesh/policy.yaml`, then:

```bash
faramesh policy reload --data-dir /var/lib/faramesh
```

## 7) Systemd Unit (Production Baseline)

Create `/etc/systemd/system/faramesh.service`:

```ini
[Unit]
Description=Faramesh Governance Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/faramesh
ExecStart=/usr/local/bin/faramesh serve \
  --policy /etc/faramesh/policy.yaml \
  --data-dir /var/lib/faramesh \
  --socket /var/run/faramesh.sock \
  --metrics-port 9108 \
  --log-level info
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Apply:

```bash
sudo systemctl daemon-reload
sudo systemctl enable faramesh
sudo systemctl start faramesh
sudo systemctl status faramesh
```

## 8) MVP Guardrails Before Public Launch

- Run behind a trusted network boundary (private subnet or internal LB).
- Restrict who can access the Unix socket.
- Keep policy files in version control and require review for changes.
- Run `faramesh audit verify` on a schedule and alert on failure.
- Back up `/var/lib/faramesh/faramesh.db` and WAL files.

## 9) Known MVP Boundaries

This runbook gets you to a usable production MVP quickly, but not full enterprise posture yet.
If you need strict zero-trust hardening, add network-level protections and staged rollout for advanced controls.
