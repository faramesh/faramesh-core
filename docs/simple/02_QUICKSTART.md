# Quickstart (Copy-Paste)

## 1) Create a policy file

Create `policy.yaml`:

```yaml
faramesh-version: '1.0'
agent-id: quickstart-agent
default_effect: permit

vars:
  max_refund: 500

tools:
  stripe/refund:
    reversibility: compensatable
    blast_radius: external

rules:
  - id: deny-destructive-shell
    match:
      tool: shell/run
      when: 'args["cmd"] matches "rm\\s+-[rf]"'
    effect: deny
    reason: destructive command blocked
    reason_code: DESTRUCTIVE_SHELL_COMMAND

  - id: defer-large-refund
    match:
      tool: stripe/refund
      when: 'args["amount"] > vars["max_refund"]'
    effect: defer
    reason: large refund needs human approval
    reason_code: HIGH_VALUE_REFUND
```

## 2) Validate policy

```bash
faramesh policy validate policy.yaml
```

## 3) Start daemon

```bash
faramesh serve --policy policy.yaml
```

## 4) In another terminal, stream decisions

```bash
faramesh audit tail
```

## 5) Run demo traffic

```bash
faramesh demo
```

## 6) Handle deferred actions

```bash
faramesh agent approve <defer-token>
# or
faramesh agent deny <defer-token>
```

## 7) Explain a deny

```bash
faramesh explain --last-deny
```
