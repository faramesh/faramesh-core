# Network Hardening Audit Canary Runbook

This runbook executes an audit-mode canary and gates promotion using live metrics.

## Goal

Use `scripts/network_hardening_canary.sh` to answer one question safely:

- Is current real traffic compatible with hardening before any enforce rollout?

## Prerequisites

- Build/tooling available to run `go run ./cmd/faramesh`.
- A valid policy file path.
- A representative traffic generator command.
- `curl` available in the shell.

## Quick Start

Run a 5-minute canary with strict bypass/deny gating:

```bash
bash scripts/network_hardening_canary.sh \
  --policy policies/default.fpl \
  --duration 300 \
  --traffic-cmd "bash tests/socket_e2e_acceptance.sh" \
  --max-audit-violations 50 \
  --max-audit-bypass 0 \
  --max-network-deny 0
```

Successful execution returns exit code `0` and writes a JSON report in:

- `.tmp/network-hardening/` by default
- or your custom `--run-dir`
- with an isolated SDK socket path per run (override via `--socket` if needed)

## Recommended Canary Thresholds

Use thresholds aligned with your baseline tolerance:

- `max-audit-violations`: small bounded value (for expected known misses)
- `max-audit-bypass`: `0` for strict rollout
- `max-network-deny`: `0` in audit canary

## Optional Private Egress Exceptions

If your staging/prod-like traffic includes approved internal targets:

```bash
--allow-private-cidrs "10.0.0.0/8,172.16.0.0/12"
--allow-private-hosts "internal.api.local,metadata.service.consul"
```

## Output Interpretation

Each report contains:

- Stage metadata (`stage`, `mode`, `duration_seconds`)
- Thresholds used
- Metric deltas:
  - `audit_violations`
  - `audit_bypass`
  - `network_deny`
  - `decisions_permit`
  - `decisions_deny`
- `status` (`PASS` or `FAIL`)
- Artifact paths for daemon/traffic logs and raw metrics snapshots

Promotion rule:

- Promote only when `status=PASS` and deltas fit your SLO/known-risk envelope.

## Failure Playbook

If canary fails:

1. Inspect `failed_checks` in the report.
2. Review daemon log from report artifacts for reason codes and hosts.
3. Fix policy/exception gaps.
4. Re-run canary until pass.

## CI/CD Gate Example

```bash
bash scripts/network_hardening_canary.sh \
  --policy policies/staging.fpl \
  --duration 180 \
  --traffic-cmd "make smoke-proxy" \
  --max-audit-violations 20 \
  --max-audit-bypass 0 \
  --max-network-deny 0
```

Use the script exit code to block promotion automatically.
