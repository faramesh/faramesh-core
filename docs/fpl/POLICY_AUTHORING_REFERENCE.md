# Faramesh FPL Policy Authoring Reference

This document is the canonical policy-writing reference for Faramesh Policy Language (FPL).
It is intentionally strict: every statement below reflects behavior implemented in this repository.

## 1. Scope and Stability

FPL is a first-class policy authoring surface for Faramesh governance.

Current guarantees:
- FPL files are parsed by `internal/core/fpl`.
- FPL policies are loaded by `policy.LoadFile()` and compiled by `policy.NewEngine()`.
- Engine-level expression compile errors are surfaced by `faramesh policy validate <file.fpl>`.
- Repository FPL assets are covered by `TestFPLAssetsCompileWithEngine`.

Stability rules for contributors:
- Prefer explicit expression context (`args.*`, `principal.*`, `delegation.*`) over implicit bare symbols.
- Do not add syntax aliases without tests and docs updates.
- Do not silently drop semantics during conversion.

## 2. Processing Model

Faramesh policy processing for FPL:
1. Parse FPL source into `fpl.Document`.
2. Convert to `policy.Doc`.
3. Validate structure and expressions.
4. Compile expressions into engine bytecode.
5. Evaluate first-match-wins at runtime.

A policy is not considered valid unless step 4 succeeds.

## 3. Canonical Rule Style

Use this style for all new policies:
- Use explicit runtime roots: `args`, `principal`, `delegation`, `session`, `tool`, `time`.
- Guard nullable string fields before `matches` checks.
- Use helper functions for array arguments instead of implicit numeric comparisons.

Examples:

```fpl
deny! shell/run when args.cmd != nil && args.cmd matches "rm -rf|mkfs|dd if="
permit stripe/refund when args.amount <= 500 && principal.verified == true
deny send_email when args_array_len("recipients") > 50
```

## 4. Language Surface (Implemented)

Top-level constructs:
- `agent <id> { ... }`
- `system <id> { ... }`
- flat rules outside blocks (`permit ...`, `deny ...`, `defer ...`)
- manifest statements (`manifest orchestrator ...`, `manifest grant ...`)

Inside `agent` blocks, parser supports:
- `default`
- `model`, `framework`, `version`
- `var`
- `budget`
- `phase`
- `rules`
- `delegate`
- `ambient`
- `selector`
- `credential`
- inline flat rules

Rule effects:
- Permit aliases: `permit`, `allow`, `approve`
- Deny aliases: `deny`, `block`, `reject`
- Defer: `defer`
- Strict deny: `deny!`

Rule clauses:
- `when <expr>`
- `notify: "target"`
- `reason: "message"`

## 5. Expression Context (Runtime)

Available objects:
- `args`
- `vars`
- `session`
- `tool`
- `principal`
- `delegation`
- `time`

Key fields:
- `session.call_count`, `session.history`, `session.cost_usd`, `session.daily_cost_usd`
- `tool.reversibility`, `tool.blast_radius`, `tool.tags`
- `principal.id`, `principal.tier`, `principal.role`, `principal.org`, `principal.verified`
- `delegation.depth`, `delegation.origin_agent`, `delegation.origin_org`, `delegation.agent_identity_verified`
- `time.hour`, `time.weekday`, `time.month`, `time.day`

Built-in helper functions:
- `history_contains_within(tool_pattern, seconds)`
- `history_sequence(tool_a, tool_b, ...)`
- `history_tool_count(tool_pattern)`
- `deny_count_within(seconds)`
- `args_array_len(path)`
- `args_array_contains(path, value)`
- `args_array_any_match(path, pattern)`
- `contains(array, value)`

## 6. Identity / IdP Authoring

To make a policy principal-aware, reference `principal.*` or `delegation.*` in `when` clauses.

Example:

```fpl
deny stripe/refund when principal.verified != true
permit stripe/refund when args.amount <= 500 && principal.verified == true
```

Operational consequence:
- `faramesh onboard` treats these expressions as requiring IdP readiness checks.

## 7. Credential Sequestration Authoring

Use `credential` blocks to declare brokered credential intent.

```fpl
credential stripe {
  scope refund read_charge
  max_scope "refund:amount<=1000"
}
```

Loader behavior:
- Adds `credential:broker` and `credential:required` tool tags.
- Adds `credential:scope:<max_scope>` tag when `max_scope` is present.
- Scope mapping:
  - If scope entry contains `/` (for example `stripe/refund`), it is used as-is.
  - If scope entry is shorthand (for example `refund`) and credential ID is `stripe`, it maps to `stripe/refund`.

## 8. Framework-Agnostic Tool Naming

FPL rule matching is glob-based and framework-agnostic.

Use patterns intentionally:
- Exact: `stripe/refund`
- Namespace: `stripe/*`
- Catch-all: `*`

Prefer policy boundaries around action classes, not framework internals.

## 9. Model / Framework Metadata

FPL `model`, `framework`, and `version` declarations are preserved as policy vars:
- `agent.model`
- `model_name`
- `agent.framework`
- `agent.version`

This allows governance expressions and telemetry to consume model metadata consistently.

## 10. FPL <-> YAML Conversion

### FPL to YAML

Use:

```bash
faramesh policy fpl yaml policy.fpl
```

Behavior:
- Emits YAML bridge format containing:
  - `faramesh-version`
  - `agent-id`
  - `default_effect`
  - `fpl_inline` (full FPL source)
- This path is intentionally lossless for rich FPL constructs.

### YAML/FPL to canonical FPL

Use:

```bash
faramesh policy fpl decompile policy.yaml
faramesh policy fpl decompile policy.fpl
```

Behavior:
- If YAML contains `fpl_inline`, decompile returns that inline FPL directly.
- Otherwise, decompile reconstructs canonical FPL from policy doc fields.

## 11. Parsed vs Enforced Coverage

Important distinction:
- Some constructs are parser-level today but not fully mapped into runtime policy schema.
- `fpl_inline` bridge output exists to prevent semantic loss for those constructs.

If adding new FPL primitives:
- Add parser support.
- Add mapping into `policy.Doc` and runtime enforcement.
- Add round-trip tests.
- Update this reference in the same change.

## 12. Validation and CI Gates

Authoring workflow:

```bash
faramesh policy validate policies/default.fpl
faramesh policy test policies/default.fpl --tool stripe/refund --args '{"amount":700}' --json
```

Repository gates should include:
- `go test ./internal/core/fpl`
- `go test ./internal/core/policy -run TestFPLAssetsCompileWithEngine`
- full suite: `go test ./...`, `go test ./... -race`, `go test ./... -tags=adversarial`

## 13. Known Non-FPL Governance Areas

Some Faramesh governance concerns are currently controlled outside FPL syntax:
- Supply-chain verification (`faramesh verify buildinfo`, signing/verification flows)
- Runtime identity provider provisioning (SPIFFE/SPIRE, cloud workload identity, external IdPs)
- External credential backend provisioning (Vault/AWS/GCP/Azure/1Password/Infisical)

FPL expresses policy intent; runtime wiring/configuration remains required.

## 14. Contributor Checklist (Required)

Before merging FPL changes:
- Policy compiles through engine (`policy validate` or `policy.NewEngine`).
- No bare implicit symbols for runtime data paths.
- Pack/example/testdata parity maintained (not only default/demo policies).
- Round-trip behavior covered for conversion paths touched.
- This reference updated if syntax or semantics changed.
