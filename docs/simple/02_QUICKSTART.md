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

## 3) Enable credential sequestration defaults

```bash
faramesh credential enable --policy policy.yaml
faramesh credential status
```

`credential status` now shows a summary-first readiness view by default.

## 4) Start runtime

```bash
faramesh up --policy policy.yaml
```

## 5) In another terminal, stream live decisions

```bash
faramesh audit tail
```

## 6) Run your agent behind governance

```bash
faramesh run --broker -- python your_agent.py
```

Optional smoke test (built-in synthetic traffic):

```bash
faramesh demo
```

## 7) Handle deferred actions

```bash
faramesh approvals
faramesh approvals show <approval-id>
faramesh approvals approve <approval-id>
# or
faramesh approvals deny <approval-id>
```

## 8) Explain and trace decisions

```bash
faramesh audit show <action-id>
faramesh explain <action-id>
faramesh explain approval <approval-id>
faramesh explain agent <agent-id>
faramesh explain run <run-or-session-id>
```
