<p align="center">
  <img src="logo.png" alt="Faramesh" width="220" />
</p>

<p align="center">
  <strong>Unified governance plane for AI agents.</strong><br/>
  Pre-execution authorization · Policy-as-code · Tamper-evident audit trail.
</p>

<p align="center">
  <a href="https://faramesh.dev">Website</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/docs">Docs</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/changelog">Changelog</a>
</p>

<p align="center">
  <a href="https://github.com/faramesh/faramesh-core/releases"><img src="https://img.shields.io/github/v/release/faramesh/faramesh-core?color=blue" alt="Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Elastic%202.0-orange.svg" alt="License" /></a>
  <a href="https://github.com/faramesh/faramesh-core/actions"><img src="https://github.com/faramesh/faramesh-core/workflows/CI/badge.svg" alt="CI" /></a>
</p>

---

## See it work in 30 seconds

```
brew install faramesh/tap/faramesh
faramesh demo
```

```
Faramesh — Unified Agent Governance
Starting synthetic agent with demo policy...

[10:00:15] PERMIT  get_exchange_rate      from=USD to=SEK              latency=11ms
[10:00:17] DENY    shell/run              cmd="rm -rf /"               scanner=SCANNER_DENY  latency=0ms
[10:00:18] PERMIT  read_customer          id=cust_abc123               latency=9ms
[10:00:20] DEFER   stripe/refund          amount=$12,000               awaiting approval  policy=defer-high-value-refund
[10:00:21] DENY    send_email             recipients=847               policy=deny-mass-email  latency=5ms

─────────────────────────────────────────────
5 actions evaluated. 2 PERMIT  2 DENY  1 DEFER
```

Zero config. Zero infrastructure. PERMIT/DENY/DEFER in under 3 seconds.

---

## The architecture principle

Every successful infrastructure control plane — Terraform, Vault, Datadog, OPA — was built on one architecture decision: **unified core + thin adapters**. Terraform has one HCL language and thin provider adapters. Vault has one core and pluggable backends. Faramesh follows the same model.

```
┌──────────────────────── FARAMESH INVARIANT CORE ────────────────────────┐
│  Policy Engine │ DPR Chain │ Session State │ DEFER Workflow │ Horizon   │
│  (YAML+expr)   │ (WAL-first│               │ (channel park) │ (SaaS)    │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ CanonicalActionRequest + DPR write
                                 │ (same format regardless of adapter)
┌────────────────────────────────▼────────────────────────────────────────┐
│                  ADAPTER STACK (auto-selected per environment)           │
│                                                                          │
│  A1: SDK Shim          A2: Local Daemon       A3: Sidecar + Proxy       │
│  Python/JS/Go/TS       Unix socket + broker   Transparent HTTP/gRPC     │
│  <60 sec on-ramp       Works everywhere       Network isolation         │
│                                                                          │
│  A4: Serverless        A5: MCP Gateway        A6: eBPF (optional)      │
│  Lambda/Cloud Run      Faramesh IS the MCP    Kernel-level on Linux     │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│  faramesh init --auto-detect                                             │
│  Detects K8s → Helm chart + NetworkPolicy + sidecar                     │
│  Detects Lambda → layer ARN + env var template                          │
│  Detects Jupyter → pip install + govern() snippet                       │
│  Detects MCP → client config change (one line)                          │
└──────────────────────────────────────────────────────────────────────────┘
```

A developer who writes a Faramesh policy for their notebook has already learned everything needed to govern their production Kubernetes fleet. Only the adapter changes — and `faramesh init` selects it automatically.

---

## Govern any agent in 60 seconds

### Python (A1 — SDK Shim)

```bash
pip install faramesh
```

```python
from faramesh import govern

# govern() wraps any callable.
# Preserves type hints, Pydantic models, LangChain @tool metadata.
governed_refund = govern(stripe_refund, policy='payment.yaml', agent_id='payment-bot')

try:
    result = governed_refund(amount=100, currency='usd')
except DenyError as e:
    print(f"DENY: {e.reason}")    # policy blocked it
except DeferredError as e:
    print(f"DEFER: approve with: faramesh agent approve {e.defer_token}")
```

`govern()` auto-starts the faramesh daemon on first call. No separate setup in development.

### LangChain

```python
from langchain.tools import tool
from faramesh import govern

@tool
def stripe_refund(amount: float, currency: str) -> str:
    """Refund a charge via Stripe."""
    ...

governed_refund = govern(stripe_refund, policy='payment.yaml', agent_id='payment-bot')
# LangChain tool metadata (name, description, args_schema) is fully preserved.
```

### Start the daemon

```bash
faramesh serve --policy payment.yaml
```

The daemon loads the policy, opens the WAL and DPR store, and starts accepting connections on `/tmp/faramesh.sock`.

---

## Policy-as-code

```yaml
# payment.yaml
faramesh-version: '1.0'
agent-id: payment-bot
default_effect: permit

vars:
  max_refund: 500

rules:
  # Deny destructive shell commands — always.
  - id: deny-destructive-shell
    match:
      tool: shell/run
      when: 'args["cmd"] matches "rm\\s+-[rf]"'
    effect: deny
    reason: destructive shell command blocked by policy
    reason_code: DESTRUCTIVE_SHELL_COMMAND

  # Require human approval for high-value refunds.
  - id: defer-high-value-refund
    match:
      tool: stripe/refund
      when: 'args["amount"] > vars["max_refund"]'
    effect: defer
    reason: refund exceeds threshold — requires finance approval
    reason_code: HIGH_VALUE_REFUND

  # Deny mass email.
  - id: deny-mass-email
    match:
      tool: send_email
      when: 'len(args["recipients"]) > 50'
    effect: deny
    reason: mass email to >50 recipients requires manual review
    reason_code: MASS_EMAIL_LIMIT
```

Policy rules are evaluated with [expr-lang](https://github.com/expr-lang/expr) — a Go-native, type-safe, sandboxed expression language. Rules compile to bytecode at load time and evaluate at ~1μs per rule.

**Validate in CI:**
```bash
faramesh policy validate policies/payment.yaml
# Parses YAML, validates rule structure, compiles all when-conditions.
# Exits 0 on success, 1 on error. Drop into any CI pipeline.
```

---

## The WAL ordering invariant

Every governance decision has a durable audit record before it is returned to the caller. No execution without an audit record — under any failure mode.

```
CanonicalActionRequest
 │
 ├─[1]  Kill switch check      atomic.Bool per agent_id — nanoseconds
 ├─[2]  Phase check            tool visible in current workflow phase?
 ├─[3]  Pre-execution scanners shell, secret, PII — parallel goroutines
 ├─[4]  Session state read     sync.Map counters + ring buffer
 ├─[5]  History ring read      last N calls within T seconds
 ├─[6]  External selector fetch lazy, parallel, cached, timeout-bounded
 ├─[7]  Policy evaluation      expr-lang bytecode, first-match-wins, ~1μs/rule
 ├─[8]  Decision               PERMIT | DENY | DEFER | SHADOW
 ├─[9]  WAL write ──────────── fsync to local disk BEFORE returning decision
 ├─[10] Async                  replicate to SQLite DPR, update session + history
 └─[11] Return Decision        to adapter
```

If step 9 fails → DENY. If the process crashes between steps 9 and 10, the WAL replays on restart. No gap in the audit chain is possible.

---

## CLI reference

```
faramesh demo                              # See governance in action (30 seconds)
faramesh init                             # Auto-detect env, generate config
faramesh serve --policy policy.yaml       # Start the governance daemon
faramesh policy validate policy.yaml      # Validate and lint a policy file
faramesh policy inspect policy.yaml       # Show compiled policy summary
faramesh audit tail                        # Stream live decisions
faramesh audit verify faramesh.db         # Verify DPR chain SHA256 integrity
faramesh agent approve <defer-token>      # Approve a pending DEFER
faramesh agent deny <defer-token>         # Deny a pending DEFER
faramesh agent kill <agent-id>            # Activate kill switch for an agent
```

---

## DEFER workflow — human-in-the-loop

```
Agent calls governed_refund(amount=12000)
  → Policy evaluates: amount > max_refund → DEFER
  → Python SDK blocks (DeferPollLoop, polls every 2s)
  → Slack notification: "Approve: faramesh agent approve abc12345"
  → Operator runs: faramesh agent approve abc12345
  → SDK unblocks, function executes
```

DEFER timeout (default 5 minutes) raises `DeferredError` with `expired=True`.

---

## DPR Chain — tamper-evident audit trail

Every decision is recorded in a per-agent chain. Each record includes:

- `record_hash` — SHA256 of this record's canonical bytes
- `prev_record_hash` — SHA256 of the previous record (linked list)
- `policy_version` — hash of the active policy at decision time
- `args_structural_sig` — shape hash of arguments (never raw values)
- `effect` — PERMIT / DENY / DEFER / SHADOW

```bash
faramesh audit verify ~/.faramesh/faramesh.db
# ✓ Chain integrity verified. 1,247 records, 0 violations.
```

---

## Architecture: OSS Core + Horizon

| OSS Core (this repo) | Horizon (enterprise) |
|---|---|
| `govern()` decorator + context manager | Multi-tenant fleet management |
| Policy YAML + expr-lang conditions | SSO + SCIM |
| DPR chain (SQLite + WAL) | Compliance exports (SOC 2, HIPAA, EU AI Act) |
| `faramesh` CLI | Managed approval workflows |
| All 6 adapters (SDK → eBPF) | Drift detection + PIE analysis |

The OSS Core gives away everything that runs at the execution boundary — the part every engineer needs. Horizon sells the management layer that large organizations require.

---

## Install

**macOS / Linux (brew):**
```bash
brew install faramesh/tap/faramesh
```

**macOS / Linux (direct):**
```bash
curl -fsSL https://faramesh.dev/install.sh | sh
```

**Docker:**
```bash
docker run --rm faramesh/faramesh demo
```

**Go:**
```bash
go install github.com/faramesh/faramesh-core/cmd/faramesh@latest
```

**Python SDK:**
```bash
pip install faramesh
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The invariant Core is the heart of the product — changes to `internal/core/` require proof that behavior is identical across all adapters.

## License

[Elastic License 2.0](LICENSE). Free to use, modify, and distribute. Cannot be offered as a hosted service without a commercial agreement.
