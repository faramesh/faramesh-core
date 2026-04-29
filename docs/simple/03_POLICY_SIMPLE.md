# Policy Writing (Simple Rules)

Policy files are YAML.

## Basic shape

```yaml
faramesh-version: '1.0'
agent-id: my-agent
default_effect: permit

rules:
  - id: rule-name
    match:
      tool: tool/id
      when: 'expression'
    effect: permit|deny|defer|shadow
    reason: human message
    reason_code: MACHINE_CODE
```

## How matching works

- Rules run top to bottom.
- First matching rule wins.
- If no rule matches, `default_effect` is used.

## Good first rules

1. Block dangerous shell commands.
2. Defer high-risk actions.
3. Permit normal low-risk actions.

## Useful examples

Deny dangerous shell:

```yaml
- id: deny-destructive-shell
  match:
    tool: shell/run
    when: 'args["cmd"] matches "rm\\s+-[rf]"'
  effect: deny
  reason: dangerous command
  reason_code: DESTRUCTIVE_SHELL_COMMAND
```

Defer large payment:

```yaml
- id: defer-large-payment
  match:
    tool: payment/transfer
    when: 'args["amount"] > 1000'
  effect: defer
  reason: high value transfer needs review
  reason_code: HIGH_VALUE_TRANSFER
```

Permit small payment:

```yaml
- id: permit-small-payment
  match:
    tool: payment/transfer
    when: 'args["amount"] <= 1000'
  effect: permit
  reason: within threshold
  reason_code: WITHIN_THRESHOLD
```

## Validate before deploy

```bash
faramesh policy validate policy.yaml
```

## Test one tool call without running daemon

```bash
faramesh policy test policy.yaml --tool payment/transfer --args '{"amount":1200}'
```

## Inspect policy summary

```bash
faramesh policy inspect policy.yaml
```
