# Chain Exfil Hardening Playbook

This guide captures the production hardening pattern for chain-based exfiltration:

- deterministic sink-tool gating using recent session history
- sink hardening (purpose + recipient/domain controls)
- strict outbound egress allowlisting
- base64/encoded payload resistance at pre-exec scan time
- async L3 intent classification consumed deterministically at gate time
- replay-driven policy tightening

## 1) Deterministic Chain Gating on Sink Tools

Use history-aware conditions on the sink tool (`draft_email_with_body`) so allowed single calls do not compose into an unsafe chain.

A ready-to-use baseline policy is provided at:

- `policies/chain_exfil_hardening.yaml`
- `policies/chain_exfil_hardening.shadow.yaml` (shadow-first canary)

Key rules in that policy:

- `history_sequence('read_customer_db', 'draft_email_with_body')` -> `deny`
- `history_contains_within('read_customer_db', 300)` -> `defer`
- `history_sequence('read_customer_db', 'proxy/http')` -> `deny`
- `history_contains_within('read_customer_db', 300)` on `proxy/http` -> `defer`

Validate before rollout:

```bash
faramesh policy validate policies/chain_exfil_hardening.yaml
```

## 2) Sink Hardening

The same policy enforces:

- purpose binding (`purpose('customer_support_response')`)
- recipient cardinality (`args_array_len('recipients') == 1`)
- domain allowlist (`args_array_any_match('recipients', '*@company.com')`)

This blocks broad recipient fanout and non-allowlisted domains even when the sink tool itself is approved.

## 3) Strict Egress Route Constraints

Policy-side host/path/method allowlists are included for `proxy/http`.

For inference proxy rewrites and forced auth/header controls, use route definitions with:

- `faramesh serve --proxy-forward --inference-routes-file <path>`

Example route file (`configs/inference-routes.json`):

```json
[
  {
    "name": "openai-responses",
    "host_pattern": "api.openai.com",
    "path_pattern": "/v1/responses",
    "methods": ["POST"],
    "upstream": "https://api.openai.com",
    "auth_type": "bearer",
    "auth_token_env": "OPENAI_API_KEY",
    "model_rewrite": "gpt-4o-mini"
  }
]
```

Start daemon with strict route controls:

```bash
faramesh serve \
  --policy policies/chain_exfil_hardening.yaml \
  --proxy-port 8080 \
  --proxy-forward \
  --inference-routes-file configs/inference-routes.json
```

## 4) Base64 Resistance in Pre-Exec Scanner

Core now applies multimodal scanning to encoded argument strings before permit.

Behavior:

- decodes base64/base64url argument values when possible
- scans decoded content for prompt/code/command injection markers
- denies on detection with reason code `MULTIMODAL_INJECTION`

This closes the gap where encoded payloads could bypass plain-text regex checks.

## 5) L3 Semantic Detection With Deterministic Gate Reads

Pattern:

1. Async classifier (outside policy eval path) computes one class from a fixed enum:
   - `routine`
   - `anomalous`
   - `potentially_adversarial`
   - `high_risk_intent`
2. Classifier writes class into session state via governed `session/write`:
   - key: `<agent-id>/intent/class`
   - value: class string
   - optional: `ttl_seconds` (clamped to 30s..24h, defaults to 10m)
3. Gate reads cached `session.intent_class` deterministically in policy `when` clauses.

Daemon wiring (async classifier -> governed session/write) is now built in.

```bash
faramesh serve \
  --policy policies/chain_exfil_hardening.yaml \
  --intent-classifier-url http://127.0.0.1:8787/v1/intent/classify \
  --intent-classifier-timeout 3s
```

Optional auth token:

```bash
faramesh serve \
  --policy policies/chain_exfil_hardening.yaml \
  --intent-classifier-url https://classifier.internal/v1/intent/classify \
  --intent-classifier-bearer-token "$INTENT_CLASSIFIER_TOKEN"
```

Example write payload:

```json
{
  "tool": "session/write",
  "args": {
    "key": "agent-1/intent/class",
    "value": "high_risk_intent",
    "ttl_seconds": 300
  }
}
```

Policy example (already in template):

```yaml
when: "session.intent_class == 'potentially_adversarial' || session.intent_class == 'high_risk_intent'"
```

## 6) Replay-Driven Tightening

Use historical WAL replay to detect where current policy misses chain variants.

```bash
faramesh policy policy-replay \
  --policy policies/chain_exfil_hardening.yaml \
  --wal /path/to/production/faramesh.wal \
  --limit 0 \
  --max-divergence 25
```

For stage-gated replay + live metric checks:

```bash
bash scripts/chain_exfil_stage_gate.sh \
  --stage-name canary-shadow \
  --policy policies/chain_exfil_hardening.shadow.yaml \
  --replay-wal /path/to/production/faramesh.wal \
  --duration 300 \
  --max-shadow-exposure 5 \
  --max-deny-delta 150 \
  --max-defer-delta 150 \
  --replay-tool-filter-regex '^(draft_email_with_body|proxy/http|read_customer_db|session/write)$' \
  --max-replay-divergence-filtered 10 \
  --max-replay-divergence 30
```

Use filtered divergence for chain-exfil signal and keep raw divergence as a broader safety net.

Rollout loop:

1. run candidate policy with shadow-safe adjustments
2. monitor `faramesh_shadow_mode_incident_exposure`
3. replay historical WAL with `policy-replay`
4. tighten sequence/sink rules where divergences persist
5. promote to enforce when replay + shadow exposure converge

## 7) Progressive Enforce

Use the progressive runner with CSV stages to move from shadow to full enforce.

Example stage manifest:

- `scripts/chain_exfil_rollout_stages.example.csv`

Run:

```bash
bash scripts/chain_exfil_progressive_rollout.sh \
  --stage-file scripts/chain_exfil_rollout_stages.example.csv \
  --replay-wal-default /path/to/production/faramesh.wal \
  --replay-tool-filter-regex '^(draft_email_with_body|proxy/http|read_customer_db|session/write)$' \
  --traffic-cmd "bash tests/socket_e2e_acceptance.sh" \
  --run-dir .tmp/chain-exfil/rollout
```

Each stage gates on:

- `faramesh_shadow_mode_incident_exposure` delta
- `faramesh_decisions_total{effect="deny"}` delta
- `faramesh_decisions_total{effect="defer"}` delta
- `faramesh policy policy-replay` divergence threshold (raw + filtered by replay tool regex)

## 8) Operational Notes

- keep chain gating on sink tools, not only on source tools
- keep egress default-deny and enumerate approved routes
- treat L3 classifier output as advisory input; enforcement remains deterministic
- tighten iteratively using replay evidence instead of one-shot rule overfitting
