# Launch Post Kit

Use this as copy-paste material for your release post.

## Short Post (X / quick update)

Faramesh Core is now live as a production-ready MVP.

What it gives you right now:
- Policy-as-code governance for agent tool calls
- Real-time PERMIT/DENY/DEFER decisions
- WAL-first tamper-evident DPR audit chain
- Live audit streaming and decision explainability

Start in minutes:
1. `faramesh policy validate /etc/faramesh/policy.yaml`
2. `faramesh serve --policy /etc/faramesh/policy.yaml --data-dir /var/lib/faramesh --metrics-port 9108`
3. `faramesh audit tail`

Production runbook:
- `docs/MVP_PRODUCTION_RUNBOOK.md`

## Long Post (LinkedIn / blog excerpt)

We just moved Faramesh Core to a deployable production MVP.

Faramesh Core is a governance daemon for AI agents that enforces policy before execution and writes a tamper-evident audit chain for every decision.

What is included in this MVP:
- Unified policy engine with first-match rule evaluation
- Pre-execution scanners and DENY/DEFER controls
- Durable WAL-first decision recording
- SQLite DPR store with optional PostgreSQL mirrored writes
- Live audit stream (`faramesh audit tail`)
- Explain tooling (`faramesh explain`) for operator investigations
- Optional adapters for proxy, gRPC, and MCP gateway modes

Operational baseline:
- Build and deploy with a single binary
- Run daemon with explicit policy and data directory
- Validate policy before rollout
- Verify DPR chain integrity as a routine check

If you want to run it now, use the runbook:
- `docs/MVP_PRODUCTION_RUNBOOK.md`

## Release Notes Snippet

### Added
- Production runbook for minimal MVP deployment
- Launch-ready post templates for immediate publishing

### Hardening included in this release cycle
- Budget session and daily cost values wired into policy evaluation context
- Horizon sync decision events now include richer metadata:
  - `agent_id`
  - `tool_id`
  - `session_id`
  - `record_id`
  - `timestamp`

### Validation
- `go test ./...` passing in faramesh-core
