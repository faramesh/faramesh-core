# CostShield — LLM Inference and API Cost Governance PRD

**Product:** Faramesh CostShield  
**Repo (planned):** Implemented as Core Layer 13 + standalone CLI tool `faramesh costshield`  
**License:** Open source (Apache 2.0) for Core integration; advanced analytics via Horizon  
**Relationship to Core:** CostShield is the cost governance subsystem of Faramesh Core. It ships as part of Core v1.1+. The name "CostShield" brands the feature set for marketing and documentation purposes.

---

## Problem Statement

The "$500 weekend bill" is a documented, recurring, and embarrassing production failure for every team deploying LLM agents. An agent with a tight loop, a misconfigured tool, or a large context window can exhaust a monthly API budget in an hour. Current solutions (monitoring dashboards, alerting) are reactive — they tell you after the money is spent.

CostShield enforces budget limits **before** the cost is incurred. It is a pre-execution enforcement mechanism, not a post-spend monitoring tool. The decision to reject a tool call because it would exceed the budget is made at the same nanosecond as all other policy decisions — it is not a separate system that has to be polled.

---

## Core Features

### Budget Enforcement in Policy YAML

```yaml
# faramesh/policy.yaml

budget:
  # Per-session limits (resets when session ends)
  session:
    max_cost_usd: 50.00
    max_calls: 200
    on_exceed: deny       # or: defer (require approval to continue)
    
  # Per-day limits (resets at midnight UTC, persists across sessions)
  daily:
    max_cost_usd: 500.00
    alert_threshold_usd: 400.00    # alert before hitting ceiling
    on_exceed: deny
    
  # Sliding window (rolling N-hour budget)
  rolling:
    window_minutes: 60
    max_cost_usd: 100.00
    on_exceed: defer

# Per-tool cost declarations
tool_costs:
  # Business tools: actual monetary cost (uses args.amount)
  stripe/charge:
    type: business
    amount_field: "args.amount"
    currency: usd
    
  stripe/refund:
    type: business
    amount_field: "args.amount"
    
  # API tools: fixed cost per call
  openai/chat:
    type: api_per_token
    cost_per_1k_input_tokens: 0.03
    cost_per_1k_output_tokens: 0.06
    token_field: "args.max_tokens"
    charge_on: attempt          # charged even if call fails
    
  anthropic/messages:
    type: api_per_token
    cost_per_1k_input_tokens: 0.008
    cost_per_1k_output_tokens: 0.024
    token_field: "args.max_tokens"
    
  send_sms:
    type: api_fixed
    cost_usd: 0.01
    charge_on: success          # only charged on successful delivery
    
  aws_lambda:
    type: api_fixed
    cost_usd: 0.0000167          # per 100ms, 128MB
    charge_on: attempt

  saas_api_call:
    type: api_fixed
    cost_usd: 0.05
    charge_on: success
```

### Budget Condition Surface in Policy Rules

```yaml
# Budget state available in when: expressions
rules:
  - id: budget-soft-limit
    match:
      tool: "openai/*"
      when: "session.daily_cost > 400"    # approaching limit
    effect: defer
    reason: "Daily LLM spend approaching limit — approve to continue"
    
  - id: session-limit-approaching
    match:
      tool: "*"
      when: "session.cost > 45"           # $5 buffer before $50 session limit
    effect: defer
    reason: "Session cost approaching limit"
```

### Atomic Budget Enforcement (No Race Conditions)

The budget check and increment are atomic via Redis Lua script (no TOCTOU window):

```lua
-- Atomic: read current cost, check against limit, increment if OK
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local cost_to_add = tonumber(ARGV[1])
local max_cost = tonumber(ARGV[2])

if current + cost_to_add > max_cost then
    return {'DENY', 'BUDGET_DAILY_LIMIT_EXCEEDED', tostring(current)}
end

redis.call('INCRBYFLOAT', KEYS[1], cost_to_add)
redis.call('EXPIRE', KEYS[1], 86400)
return {'PERMIT', '', tostring(current + cost_to_add)}
```

Without atomic enforcement, two concurrent calls can both read $480, both evaluate as under the $500 limit, and both execute — spending $500 total while the policy believed the limit was $490.

### Two-Phase Cost Accounting (Cost Reservation)

For dynamic-cost tools where the exact cost is only known after execution:

1. **Pre-execution**: Reserve the maximum possible cost (e.g., `max_tokens` × token_cost)
2. **Post-execution**: Settle to actual cost (actual tokens used × token_cost)

This prevents budget overshoot when actual costs are less than maximums while correctly blocking calls that would exceed the budget even at minimum cost.

```python
# Tool declares max cost for reservation
@govern(agent_id="my-bot", tool_meta=ToolMeta(
    max_cost_usd=lambda args: args.get("max_tokens", 4096) * 0.00003
))
def openai_chat(messages: list, max_tokens: int = 4096) -> str:
    response = openai.chat.completions.create(...)
    # Report actual cost after execution
    faramesh.settle_cost(actual_usd=response.usage.total_tokens * 0.00003)
    return response.choices[0].message.content
```

### Cross-Service Aggregate Budget

Total economic exposure across all tools, not just per-service:

```yaml
budget:
  aggregate:
    description: "Total economic exposure across all tools"
    max_cost_usd: 1000.00
    window: daily
    on_exceed: deny
    # Includes business costs (Stripe charges) + API costs (OpenAI tokens)
    # in a unified $ denominator
```

### LLM Inference Budget (Special Case)

The most common CostShield use case: preventing runaway LLM inference costs.

```yaml
# LLM-specific budget controls (enforced BEFORE the LLM call is made)
budget:
  llm:
    max_tokens_per_session: 100000
    max_inference_cost_usd_per_session: 2.00
    max_llm_calls_per_session: 50
    max_tokens_per_call: 8192       # hard cap per individual call
    on_exceed: deny
    
  llm_daily:
    max_tokens: 1000000
    max_cost_usd: 50.00
    alert_threshold_usd: 40.00
    on_exceed: deny
```

---

## CLI Commands

```bash
# View current cost state for an agent
faramesh costshield status --agent payment-bot

  CostShield Status — payment-bot
  ──────────────────────────────────
  Session cost:  $23.47 / $50.00  (47%)  ████████░░░░░░░░
  Daily cost:    $187.23 / $500.00 (37%) ██████░░░░░░░░░░
  Session calls: 143 / 200        (72%)  ████████████░░░░
  
  Top cost drivers (this session):
    openai/chat:    $18.20 (77%) — 42 calls
    stripe/refund:  $4.50  (19%) — 9 calls × $0.50 avg
    send_sms:       $0.77  (3%)  — 77 calls × $0.01

# Reset session cost (manual override with reason)
faramesh costshield reset --agent payment-bot --session --reason "authorized by ops team"

# View cost history
faramesh costshield history --agent payment-bot --last 7d

# Set ad-hoc cost alert
faramesh costshield alert --agent payment-bot --daily-threshold 400
```

---

## DPR Integration

Every tool call DPR record includes cost fields:

```json
{
  "record_id": "dpr_abc123",
  "tool_id": "openai/chat",
  "effect": "PERMIT",
  "cost_reserved_usd": 0.245,
  "cost_actual_usd": 0.187,
  "cost_type": "api_per_token",
  "cost_charge_event": "attempt",
  "session_cost_before_usd": 23.47,
  "daily_cost_before_usd": 187.23
}
```

This makes cost governance fully auditable: you can reconstruct exactly how much each decision contributed to session and daily spend.

---

## Build Order

1. **v1.1 (Core)**: Basic budget enforcement (daily_usd, session_usd) in pipeline with PostgreSQL/Redis backing
2. **v1.2 (Core)**: Tool cost declarations in policy YAML, atomic Redis Lua enforcement
3. **v1.3 (Core)**: Two-phase cost reservation, LLM inference budget
4. **v1.4 (Core)**: Cross-service aggregate budget, rolling window budgets
5. **Horizon**: CostShield dashboard — per-agent cost analytics, cost anomaly detection, budget utilization trends
