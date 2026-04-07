# Network Hardening Progressive Enforce Runbook

This runbook executes staged audit/enforce rollout using a stage manifest.

## Goal

Use `scripts/network_hardening_progressive_rollout.sh` to move from canary audit to enforce in controlled stages with hard stop on failed gates.

## Stage File Format

Create a CSV manifest (or start from `scripts/network_hardening_rollout_stages.example.csv`):

```csv
name,mode,policy,duration,max_network_deny,max_audit_violations,max_audit_bypass
canary-audit,audit,policies/default.fpl,300,0,50,0
staging-enforce-10,enforce,policies/staging_enforce_10.fpl,300,15,200,10
staging-enforce-50,enforce,policies/staging_enforce_50.fpl,300,25,200,10
prod-enforce-10,enforce,policies/prod_enforce_10.fpl,300,20,200,10
prod-enforce-50,enforce,policies/prod_enforce_50.fpl,300,30,200,10
prod-enforce-100,enforce,policies/prod_enforce_100.fpl,300,40,200,10
```

Field meaning:

- `name`: stage label in logs/reports
- `mode`: `audit` or `enforce`
- `policy`: policy file for that stage
- `duration`: observation window seconds
- `max_network_deny`: max hardening deny delta for the stage
- `max_audit_violations`: max audit violation delta
- `max_audit_bypass`: max audit bypass delta

## Repository Defaults

The staged policy files referenced in the example manifest are present in-repo:

- `policies/staging_enforce_10.fpl`
- `policies/staging_enforce_50.fpl`
- `policies/prod_enforce_10.fpl`
- `policies/prod_enforce_50.fpl`
- `policies/prod_enforce_100.fpl`

These are baseline seed files copied from `policies/default.fpl` and must be tuned for real domain/agent scope before staging or production rollout.

Current baseline profile now includes staged `proxy/connect` and `proxy/http` host/path allowlists for:

- `api.openai.com` (`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings` by stage)
- `api.anthropic.com` (`/v1/messages` by stage)
- `*.openai.azure.com` (`/openai/deployments/*/chat/completions` with `api-version=*` at prod 100 stage)

Treat these as starting defaults; replace with your approved internal/provider endpoints as part of rollout signoff.

## Execute Rollout

```bash
bash scripts/network_hardening_progressive_rollout.sh \
  --stage-file scripts/network_hardening_rollout_stages.example.csv \
  --traffic-cmd "make smoke-proxy" \
  --run-dir .tmp/network-hardening/rollout
```

Default behavior:

- Stops on first stage failure.
- Exits non-zero when any stage fails.
- Writes per-stage JSON report and one summary file.

Use `--continue-on-fail` for full diagnostic pass without early stop.

## Progressive Strategy (Recommended)

1. Run audit canary stage with strict bypass/deny thresholds.
2. Start enforce on lowest-risk domains/agents using a narrower policy.
3. Expand enforce policy by stage (10% -> 50% -> 100% of target traffic scope).
4. Promote only when every stage passes gate thresholds and on-call signoff is complete.

## Rollback Criteria

Rollback to previous stage (or to audit) if any condition occurs:

- Stage exits `FAIL`
- Unexpected deny surge beyond stage threshold
- User-facing error-rate or latency SLO regression

## Artifacts Produced

- Per-stage report JSON in `--run-dir`
- One rollout summary text file
- Daemon and traffic logs for each stage
- Raw metrics snapshots per stage

These artifacts should be attached to release evidence for change approval.
