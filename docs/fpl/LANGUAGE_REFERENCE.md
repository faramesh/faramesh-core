# FPL Language Reference

**Faramesh Policy Language (FPL)** is a domain-specific language for AI agent governance. It compiles to the same internal representation as YAML but provides agent-native primitives as first-class constructs.

## Why FPL exists

Governing AI agents today requires someone who understands authorization concepts, YAML schema, and the agent framework. FPL changes that. A compliance officer, CISO, or product manager can read and write FPL without understanding OPA Rego or YAML conventions. With natural language compilation, anyone who can describe a business rule in English can produce verified, backtested, production-ready governance policy.

## What makes FPL different

| Feature | OPA/Rego | Cedar | YAML+expr | FPL |
|---------|----------|-------|-----------|-----|
| Sessions | No | No | Convention | First-class |
| Purposes | No | No | Convention | First-class |
| Delegation chains | No | No | Convention | First-class |
| Workflow phases | No | No | Convention | First-class |
| Budget enforcement | No | No | Convention | First-class |
| Ambient authority | No | No | Convention | First-class |
| Human approval | No | No | Convention | First-class |
| Mandatory deny (`deny!`) | Convention | Convention | Convention | Compiler-enforced |
| NLP input | No | No | No | Built-in |

## Four input modes, one representation

1. **FPL directly** — structured, readable, agent-native syntax
2. **YAML** — always supported, interchange format
3. **Natural language** — `faramesh policy compile "deny all shell commands"` calls an LLM, produces FPL, validates and backtests it before activation
4. **Code annotations** — `@faramesh.tool(defer_above=500)` extracted to FPL automatically

## File extension

`.fpl`

## Comments

```fpl
# This is a comment. Comments start with # and extend to end of line.
```

## Top-level blocks

An FPL document contains one or more `agent` blocks and optionally one `system` block.

```fpl
agent <agent-id> {
  ...
}

system <system-id> {
  ...
}
```

## Agent block

The `agent` block is the primary unit. It declares everything about how one agent is governed.

```fpl
agent payment-bot {
  default deny          # default effect when no rule matches
  model "gpt-4o"        # model identity
  framework "langgraph" # framework identity

  # ... sub-blocks ...
}
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `default` | `deny` or `permit` | What happens when no rule matches |
| `model` | string | Model powering this agent |
| `framework` | string | Framework this agent runs on |
| `version` | string | Policy version identifier |
| `var` | name value | Named variable for use in conditions |

## Budget block

Controls how much an agent can spend.

```fpl
budget session {
  max $500            # maximum per session
  daily $2000         # maximum per day
  max_calls 100       # maximum tool calls per session
  on_exceed deny      # what happens when limit is hit
}
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `max` | currency | Maximum spend per session |
| `daily` | currency | Maximum spend per calendar day |
| `max_calls` | integer | Maximum tool invocations per session |
| `on_exceed` | `deny` or `defer` | Effect when a limit is exceeded |

Currency values use `$` prefix: `$500`, `$2000.50`.

## Phase block

Defines workflow phases that scope which tools are visible.

```fpl
phase intake {
  permit read_customer
  permit get_order
}

phase execution {
  permit stripe/refund
  permit send_notification
}
```

Each phase contains rules. Tools listed in a phase are only visible during that phase.

## Rules block

Contains governance rules. Rules are evaluated top to bottom (first match wins).

```fpl
rules {
  deny! shell/* reason: "never shell"
  defer stripe/refund when amount > 500 notify: "finance" reason: "high value"
  permit stripe/* when amount <= 500
  deny read_customer when not purpose("refund_processing") reason: "purpose required"
}
```

### Rule syntax

```
effect tool [when condition] [notify: target] [reason: message]
```

### Effects

| Effect | Meaning |
|--------|---------|
| `permit` | Allow the tool call |
| `deny` | Block the tool call |
| `deny!` | **Mandatory deny** — compiler-enforced, cannot be overridden by any child policy, position, or priority |
| `defer` | Pause the tool call and route to a human for approval |
| `allow` | Alias for `permit` |
| `approve` | Alias for `permit` |
| `block` | Alias for `deny` |
| `reject` | Alias for `deny` |

### Tool patterns

Tool identifiers support glob patterns:

- `stripe/refund` — exact match
- `stripe/*` — all tools in the stripe namespace
- `shell/*` — all shell tools
- `*` — all tools

### When conditions

Conditions are expr-lang expressions evaluated against the call context:

```fpl
when amount > 500
when args["cmd"] matches "rm -rf"
when session.sum(stripe/refund.amount, window=1h) > 2000
when not purpose("refund_processing")
when selectors.risk.score > 0.8
```

Available variables: `args`, `vars`, `session`, `tool`, `selectors`.

### Notify clause

Routes the decision notification to a channel or person:

```fpl
notify: "finance-team"
notify: "amjad@company.com"
```

### Reason clause

Human-readable explanation recorded in the DPR:

```fpl
reason: "aggregate refund limit exceeded"
```

## Mandatory deny (`deny!`)

The `deny!` effect is a compile-time guarantee. When a rule uses `deny!`:

1. No subsequent `permit` rule can override it
2. No child policy in an `extends` chain can override it
3. No priority field can override it
4. The compiler verifies this structurally — it is not a runtime convention

```fpl
deny! shell/run when cmd matches "rm -rf|DROP TABLE|terraform destroy"
```

## Delegate block

Declares permitted agent-to-agent delegation.

```fpl
delegate fraud-check-bot {
  scope "stripe/refund:amount<=500"
  ttl 24h
  ceiling inherited    # delegate cannot exceed my scope
}
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `scope` | string | What the delegate is allowed to do |
| `ttl` | duration | How long the delegation is valid |
| `ceiling` | `inherited` or custom | Scope ceiling for the delegate |

## Ambient block

Guards against slow accumulation attacks across a session.

```fpl
ambient {
  max_customers_per_day 1000
  max_data_volume 10mb
  on_exceed deny
}
```

## Selector block

Declares external data sources fetched at policy evaluation time.

```fpl
selector account {
  source "https://api.internal/account"
  cache 30s
  on_unavailable deny
  on_timeout deny
}
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `source` | URL | HTTP endpoint to fetch |
| `cache` | duration | How long to cache responses |
| `on_unavailable` | effect | What to do if the source is down |
| `on_timeout` | effect | What to do if the source times out |

## Credential block

Declares credential scope constraints for the credential broker.

```fpl
credential stripe {
  scope refund read_charge
  max_scope "refund:amount<=1000"
}
```

## System block

Configures system-wide settings.

```fpl
system global {
  version "1.0"
  on_policy_load_failure deny_all
  max_output_bytes 1048576
}
```

## Manifest topology (multi-agent)

For multi-agent orchestration, declare topology inline:

```fpl
manifest orchestrator payment-bot undeclared deny
manifest grant payment-bot to stripe-agent max 50
manifest grant payment-bot to approval-worker max 0 approval
```

## Complete example

```fpl
agent payment-bot {
  default deny
  model "gpt-4o"
  framework "langgraph"

  budget session {
    max $500
    daily $2000
    max_calls 100
    on_exceed deny
  }

  phase intake {
    permit read_customer
    permit get_order
  }

  phase execution {
    permit stripe/refund
    permit send_notification
  }

  rules {
    deny! shell/* reason: "never shell"

    defer stripe/refund
      when amount > 500
      notify: "finance"
      reason: "high value refund"

    permit stripe/*
      when amount <= 500

    deny read_customer
      when not purpose("refund_processing")
      reason: "purpose required"
  }

  delegate fraud-check-bot {
    scope "stripe/refund:amount<=500"
    ttl 24h
    ceiling inherited
  }

  ambient {
    max_customers_per_day 1000
    max_data_volume 10mb
    on_exceed deny
  }

  selector account {
    source "https://api.internal/account"
    cache 30s
    on_unavailable deny
  }

  credential stripe {
    scope refund read_charge
    max_scope "refund:amount<=1000"
  }
}

system global {
  version "1.0"
  on_policy_load_failure deny_all
}
```

The equivalent YAML is 60+ lines. The FPL is 50 lines with more readable structure.

## CLI commands

```bash
# Parse and compile FPL
faramesh policy fpl payment.fpl

# Compile natural language to FPL
faramesh policy compile "deny all shell commands, defer refunds over $500"

# Validate FPL (CI-safe)
faramesh policy validate payment.fpl

# Diff two policies
faramesh policy diff old.fpl new.fpl

# Backtest against real history
faramesh policy backtest payment.fpl --window 7d

# Hot-reload into running daemon
faramesh policy activate payment.fpl
```

## Durations

| Unit | Meaning |
|------|---------|
| `s` | seconds |
| `m` | minutes |
| `h` | hours |
| `d` | days |
| `w` | weeks |

## Data sizes

| Unit | Meaning |
|------|---------|
| `kb` | kilobytes |
| `mb` | megabytes |
| `gb` | gigabytes |

## GitOps workflow

FPL files are plain text. Store them in git, review in PRs, validate in CI:

```yaml
# .github/workflows/policy-gate.yml
- run: faramesh policy validate policy/*.fpl
- run: faramesh policy backtest policy/payment.fpl --window 7d
```

Policy versions are SHA-hashed and tracked in every DPR record, providing full traceability from decision back to the exact policy version that produced it.
