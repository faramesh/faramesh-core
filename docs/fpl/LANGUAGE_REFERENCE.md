# FPL Language Reference (Complete, Runtime-Accurate)

This document is the authoritative reference for what FPL can parse and what the Faramesh runtime will actually load and enforce today.

Use this reference when you need precise, implementation-level behavior.
If you want a plain-language, non-technical walkthrough, use docs/fpl/SIMPLE_TERMS_GUIDE.md.

## 1) What FPL Is

FPL (Faramesh Policy Language) is a policy DSL for governing agent tool calls.

Core model:

- Rules are evaluated in order.
- First matching rule wins.
- If nothing matches, `default` effect is applied.
- Conditions (`when`) are compiled at load-time and evaluated at runtime.

## 2) Fast Start Example

```fpl
agent payment-bot {
  default deny

  budget session {
    max $500
    daily $2000
    max_calls 100
    on_exceed deny
  }

  rules {
    deny! shell/* reason: "never run shell"
    defer stripe/refund when amount > 500 notify: "finance" reason: "high value refund"
    permit stripe/refund when amount <= 500
  }
}
```

## 3) File Format and Lexical Rules

- Extension: `.fpl`
- Encoding: UTF-8
- Comments: line comments using `#`
- Strings: both double-quoted and single-quoted forms are accepted
- Whitespace: spaces/newlines are flexible; blocks use `{ ... }`

## 4) Top-Level Constructs

Top-level statements accepted by the parser:

- `agent <id> { ... }`
- `system <id> { ... }`
- `manifest ...` topology lines
- flat rules (`permit ...`, `deny ...`, `defer ...`) outside blocks

Runtime loading constraints for standalone `.fpl`:

- at most one `agent` block
- at most one `system` block
- top-level flat rules are allowed

## 5) Rule Syntax and Semantics

Rule form:

```text
effect tool [when <expr>] [notify: <target>] [reason: <message>]
```

Supported effects:

- `permit` (aliases: `allow`, `approve`)
- `deny` (aliases: `block`, `reject`)
- `deny!` (strict deny)
- `defer`

Behavior:

- `deny!` is normalized to `deny` with strict-deny metadata.
- If `when` is omitted, runtime treats it as always true.
- `notify` and `reason` are preserved.

Tool pattern matching:

- exact: `stripe/refund`
- wildcard namespace: `stripe/*`
- catch-all: `*`

Matching uses glob semantics (`path.Match` behavior).

## 6) Agent Block: Complete Field Reference

Inside `agent <id> { ... }`, parser accepts:

- `default <deny|permit>`
- `model <value>`
- `framework <value>`
- `version <value>`
- `var <name> <value>`
- `budget <id> { ... }`
- `phase <name> { ... }`
- `rules { ... }`
- `delegate <target> { ... }`
- `ambient { ... }`
- `selector <id> { ... }`
- `credential <id> { ... }`
- flat rule lines directly in the agent block

Runtime lowering notes:

- `model`, `framework`, `version` are lowered into `vars`:
  - `agent.model`, `model_name`
  - `agent.framework`
  - `agent.version`
- multiple `budget` blocks parse, but runtime loader only accepts one.

## 7) Budget Block

Syntax:

```fpl
budget session {
  max $500
  daily $2000
  max_calls 100
  on_exceed deny
}
```

Fields:

- `max` -> session USD cap
- `daily` -> daily USD cap
- `max_calls` -> call count cap
- `on_exceed` -> expected values are `deny` or `defer`

Notes:

- currency symbol `$` is optional in parser for numeric values
- runtime uses the first budget block only

## 8) Phase Block

Syntax:

```fpl
phase intake {
  permit read_customer
  deny shell/*
  duration 15m
  next execution
}
```

Fields:

- rule lines inside phase (also populate phase tool list)
- `duration`
- `next`

Notes:

- phase rules are lowered into normal rule evaluation order after agent-level rules
- `duration` and `next` parse and lower to YAML phase fields

## 9) Rules Block

Syntax:

```fpl
rules {
  deny! shell/* reason: "never shell"
  defer stripe/refund when amount > 500
  permit stripe/* when amount <= 500
}
```

Equivalent to writing those rule lines directly in the agent block.

## 10) Delegate Block

Syntax:

```fpl
delegate approval-worker {
  scope stripe/refund
  ttl 1h
  ceiling approval
}
```

Fields:

- `scope`
- `ttl`
- `ceiling`

Runtime constraints:

- `ttl` must be a valid duration
- `ceiling` must be one of:
  - `inherited`
  - `approval`

Lowering behavior:

- adds target to orchestrator allowlist
- `ceiling approval` sets `requires_prior_approval: true`
- delegate constraints are lowered to `delegation_policies`

Decompile behavior for YAML -> FPL:

- if YAML has unsupported ceiling values (for example `$500`), decompile emits `approval` (fail-closed) and prints a lossy warning
- `--strict-lossless` fails instead of emitting a lossy conversion

## 11) Ambient Block

Syntax:

```fpl
ambient {
  max_customers_per_day 100
  max_calls_per_day 500
  max_data_volume 2mb
  on_exceed defer
}
```

Supported runtime limit keys:

- `max_customers_per_day`
- `max_calls_per_day`
- `max_data_volume`

Other keys parse but are rejected by runtime loader.

`on_exceed` runtime values:

- `deny`
- `defer`

Lowering:

- ambient limits are lowered to principal-scoped `cross_session_guards` with a 24h window.

## 12) Selector Block

Syntax:

```fpl
selector account {
  source "https://context.internal/account"
  cache 60s
  on_unavailable deny
  on_timeout defer
}
```

Fields:

- `source`
- `cache`
- `on_unavailable`
- `on_timeout`

Runtime constraints:

- `source` is required
- `cache` must be a valid duration if present
- `on_unavailable` and `on_timeout` must be `deny` or `defer`

Lowering:

- selector maps to `context_guards`:
  - `source` -> `endpoint`
  - `cache` -> `max_age_seconds`
  - `on_unavailable` -> `on_missing`
  - `on_timeout` -> `on_stale`

## 13) Credential Block

Syntax:

```fpl
credential stripe {
  scope refund read_charge
  max_scope "refund:amount<=1000"
  backend vault
  path secret/data/stripe/live
  ttl 15m
}
```

Fields:

- `scope` (one or more targets)
- `max_scope`
- `backend`
- `path`
- `ttl`

Lowering behavior:

- credentials are lowered into tool metadata tags
- required tags always include:
  - `credential:broker`
  - `credential:required`
- optional tags are emitted for configured metadata
- shorthand scope names without `/` are expanded with credential ID namespace
  - `scope refund` under `credential stripe` also applies to `stripe/refund`

## 14) System Block

Parser accepts:

- `version`
- `on_policy_load_failure`
- `kill_switch_default`
- `max_output_bytes`

Runtime loader constraints:

- `on_policy_load_failure` must be `deny` or `deny_all`
- `kill_switch_default` is currently rejected in standalone FPL loading
- `max_output_bytes` must be >= 0

## 15) Manifest Topology

Supported lines:

```fpl
manifest orchestrator payment-bot undeclared deny
manifest grant payment-bot to stripe-agent max 50
manifest grant payment-bot to approval-worker max 0 approval
```

Rules:

- grant entries must use the same orchestrator ID
- `max` must be a non-negative integer
- optional trailing `approval` enables prior-approval requirement

Lowering target:

- `orchestrator_manifest`

## 16) When Expression Environment (Complete)

### 16.1 Objects and fields

- `args` -> raw tool arguments map
- `vars` -> policy variables map
- `session.call_count`
- `session.history`
- `session.cost_usd`
- `session.daily_cost_usd`
- `tool.reversibility`
- `tool.blast_radius`
- `tool.tags`
- `principal.id`
- `principal.tier`
- `principal.role`
- `principal.org`
- `principal.verified`
- `delegation.depth`
- `delegation.origin_agent`
- `delegation.origin_org`
- `delegation.agent_identity_verified`
- `time.hour`
- `time.weekday` (1=Mon, 7=Sun)
- `time.month`
- `time.day`

### 16.2 Built-in aliases

- `amount` -> numeric alias for `args.amount` (defaults to 0)
- `cmd` -> string alias for `args.cmd` (defaults to empty string)
- `host` -> string alias for `args.host`
- `path` -> string alias for `args.path`
- `tool_name` -> current tool ID
- `recipients` -> `args_array_len("recipients")`

### 16.3 Built-in helper functions

- `purpose(expected)`
- `history_contains_within(tool_pattern, seconds)`
- `history_sequence(tool_a, tool_b, ...)`
- `history_tool_count(tool_pattern)`
- `deny_count_within(seconds)`
- `args_array_len(path)`
- `args_array_contains(path, value)`
- `args_array_any_match(path, pattern)`
- `contains(arr, s)` for string array membership

### 16.4 Custom extension points

- custom operators are injected from the process-wide operator registry
- custom selectors are injected from the process-wide selector registry

If your deployment does not register custom operators/selectors, only built-ins are available.

### 16.5 Compile-time strictness and limits

- unknown names/functions fail compilation
- expression must compile to boolean
- hard limits:
  - max chars: 1024
  - max function calls: 32
  - max operator tokens: 96
  - max nesting depth: 16

## 17) Embedded FPL in YAML

YAML policy docs can embed FPL through:

- `fpl_inline`
- `fpl_files`

Embedded FPL constraints:

- only flat rule and manifest snippets are allowed
- embedded `agent` and `system` blocks are rejected (fail-closed)

## 18) Runtime Rejections (Important)

Standalone `.fpl` parse success does not always mean runtime-loadable success.

Known runtime rejections include:

- multiple `agent` blocks
- multiple `system` blocks
- multiple `budget` blocks in one agent
- unsupported delegate ceiling values (anything except `inherited` or `approval`)
- unsupported ambient keys
- unsupported guard effects for ambient/selector blocks
- unsupported `system` settings as described above

Always run validation after edits.

## 19) YAML -> FPL Decompile Behavior

Command:

```bash
faramesh policy decompile policy.yaml
```

Strict lossless mode:

```bash
faramesh policy decompile policy.yaml --strict-lossless
```

Behavior:

- decompiler emits runtime-lowerable FPL blocks where representable
- non-representable YAML fields are warned as lossy
- with `--strict-lossless`, any lossy warning becomes a hard failure

## 20) CLI Workflow for Authors

```bash
# 1) Validate syntax + runtime-loadability + expression compile
faramesh policy validate policy.fpl

# 2) Machine-readable diagnostics
faramesh policy validate policy.fpl --json

# 3) Parse/compile FPL IR preview
faramesh policy fpl --json policy.fpl

# 4) Run deterministic fixture suite
faramesh policy suite policy.fpl --fixtures tests/policy_suite_fixtures.yaml

# 5) Replay historical decisions (counterfactual)
faramesh policy policy-replay --policy policy.fpl --wal /path/to/records.wal
```

## 21) Troubleshooting

Common validation failures and what they mean:

- `invalid when expression: unknown name ...`
  - expression references a symbol not available in the eval environment
- `delegate ... ceiling ... unsupported`
  - use `inherited` or `approval`
- `ambient limit ... unsupported`
  - use only supported ambient keys
- `... cache ... is invalid`
  - invalid duration format
- `multiple ... blocks are not runtime-loadable`
  - reduce to one supported block for current loader

## 22) Compatibility Summary

FPL authoring is production-usable today for:

- core rule governance (permit/deny/defer/strict deny)
- budget, phases, credential metadata, delegation constraints, ambient limits, selector guards
- topology manifests (`manifest orchestrator/grant`)

Some parser-level constructs still have runtime restrictions. Use `policy validate` as the source of truth for what is deployable.
