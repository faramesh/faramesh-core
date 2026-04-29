# FPL in Simple Terms (For CISOs and Non-Technical Policy Authors)

This guide explains FPL without code-heavy language.
If you need exact syntax details, use docs/fpl/LANGUAGE_REFERENCE.md.

## 1) What You Are Controlling

Think of FPL as traffic control for agent actions:

- `permit` means allow the action now.
- `deny` means block the action now.
- `defer` means pause and ask for human review.
- `default deny` means if nothing matches, the action is blocked.

This is the recommended safety posture: allow only what you clearly intend.

## 2) The Smallest Useful Policy

```fpl
agent my-agent {
  default deny

  rules {
    permit http/get
    deny shell/* reason: "shell is not allowed"
  }
}
```

How to read this:

- The agent can do `http/get`.
- Any shell command is blocked.
- Everything else is blocked because of `default deny`.

## 3) Decision Order (Very Important)

Rules are checked top to bottom.
The first matching rule wins.

Example:

```fpl
rules {
  deny stripe/*
  permit stripe/refund
}
```

In this example, `stripe/refund` is denied, because `deny stripe/*` matches first.

## 4) Business-Friendly Building Blocks

## 4.1 Require human approval for risky actions

```fpl
rules {
  defer stripe/refund when amount > 500 notify: "finance" reason: "high value refund"
  permit stripe/refund when amount <= 500
}
```

## 4.2 Block dangerous tools entirely

```fpl
rules {
  deny! shell/* reason: "never run shell"
}
```

`deny!` is a strict deny marker.

## 4.3 Restrict by role

```fpl
rules {
  permit stripe/refund when principal.role == "finance_admin"
  deny stripe/refund reason: "role required"
}
```

## 4.4 Restrict by time window

```fpl
rules {
  permit db/query when time.hour >= 8 && time.hour < 18
  deny db/query reason: "outside approved hours"
}
```

## 4.5 Detect suspicious repetition

```fpl
rules {
  deny stripe/refund when history_tool_count("stripe/refund") > 20 reason: "volume threshold exceeded"
}
```

## 5) Delegation, Ambient Limits, and Selectors (Plain English)

These are advanced controls.

## 5.1 Delegate

Use this when one agent can call another agent.

```fpl
delegate approval-worker {
  scope stripe/refund
  ttl 1h
  ceiling approval
}
```

Meaning:

- only this scope is delegated
- delegation expires after 1 hour
- approval is required for delegated execution

## 5.2 Ambient

Use this for per-principal daily limits.

```fpl
ambient {
  max_customers_per_day 100
  max_calls_per_day 500
  max_data_volume 2mb
  on_exceed defer
}
```

Meaning:

- cap daily reach and call volume
- when cap is hit, escalate for review

## 5.3 Selector

Use this to demand fresh external context before high-risk actions.

```fpl
selector account {
  source "https://context.internal/account"
  cache 60s
  on_unavailable deny
  on_timeout defer
}
```

Meaning:

- fetch account context from source
- use cached value for 60 seconds
- deny if context is unavailable
- defer if context lookup times out

## 6) What You Can Use in Conditions (`when`)

Common fields:

- `args` (tool input arguments)
- `vars` (policy variables)
- `session` (session counters/history/cost)
- `tool` (tool metadata)
- `principal` (who initiated request)
- `delegation` (delegation chain metadata)
- `time` (hour, weekday, month, day)

Handy shortcuts:

- `amount` (same as numeric `args.amount`)
- `tool_name`
- `purpose("...")`
- `history_contains_within(...)`
- `history_sequence(...)`
- `history_tool_count(...)`
- `deny_count_within(...)`
- `args_array_len(...)`
- `args_array_contains(...)`
- `args_array_any_match(...)`

## 7) Validate Before Shipping

Run this every time:

```bash
faramesh policy validate policy.fpl
```

For machine-readable diagnostics:

```bash
faramesh policy validate policy.fpl --json
```

If validation fails, do not deploy yet.

## 8) Safe Authoring Workflow

1. Start with `default deny`.
2. Add only the minimum `permit` rules required.
3. Add `defer` for high-value or high-risk actions.
4. Add explicit `deny` for dangerous tools and abuse patterns.
5. Run validate and fixture tests before release.

## 9) Common Mistakes

- Mistake: putting broad permit rules first.
- Fix: place specific deny/defer rules before broad permit rules.

- Mistake: assuming a condition name exists.
- Fix: use only documented fields/functions and run validate.

- Mistake: forgetting fallback behavior.
- Fix: keep `default deny` unless you intentionally want fail-open.

## 10) Copy-Paste Starter Policies

## 10.1 Conservative finance assistant

```fpl
agent finance-assistant {
  default deny

  rules {
    deny! shell/* reason: "shell blocked"

    defer stripe/refund when amount > 500 notify: "finance" reason: "high-value refund"

    permit stripe/refund when amount <= 500 && principal.role == "finance_admin"
    permit http/get
  }
}
```

## 10.2 Internal research assistant

```fpl
agent research-assistant {
  default deny

  rules {
    permit http/get
    permit search/query

    deny http/post reason: "outbound write blocked"
    deny shell/* reason: "shell blocked"
  }
}
```

## 11) Author Checklist

- Is `default deny` set?
- Are dangerous tools explicitly denied?
- Are high-risk actions deferred for approval?
- Are role/time/history constraints in place where needed?
- Does `faramesh policy validate` pass?

If all answers are yes, your policy is in a strong starting state.
