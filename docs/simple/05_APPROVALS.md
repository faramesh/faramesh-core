# Approvals (DEFER)

When a rule returns `defer`, Faramesh pauses the action and waits for a human decision.

## List pending approvals

```bash
faramesh approvals
```

Default output is a human-readable queue view.

```text
Approval Queue
NOTE: 2 pending approval(s)
APPROVAL ID     AGENT         TOOL             AGE  CONTEXT
approval_abc    stripe-agent  stripe/customer  2m   create customer for enterprise account
approval_def    stripe-agent  stripe/refund    9m   refund above configured threshold
```

Use raw payload mode only when needed:

```bash
faramesh approvals --json
```

Watch pending approvals in real time:

```bash
faramesh approvals watch
```

Show approval/evaluation history for an agent:

```bash
faramesh approvals history --agent <agent-id>
```

## Approve action

```bash
faramesh approvals approve <approval-id>
```

## Deny action

```bash
faramesh approvals deny <approval-id>
```

## Inspect one deferred action

```bash
faramesh approvals show <approval-id>
```

Default output includes summary + next actions:

```text
Approval Detail
Approval ID: approval_abc
Status:      PENDING
Agent:       stripe-agent
Tool:        stripe/customer
Context:     create customer for enterprise account
NEXT STEP: Approve: faramesh approvals approve approval_abc --reason "approved"
NEXT STEP: Deny: faramesh approvals deny approval_abc --reason "denied"
NEXT STEP: Explain: faramesh explain approval approval_abc
```

## Open approvals UI

```bash
faramesh approvals ui
```

`faramesh approvals ui` opens the approvals inbox. If dashboard UI is unavailable,
Faramesh automatically serves a built-in fallback inbox for approve/deny workflows.

## Kill switch for an agent

```bash
faramesh agent kill <agent-id>
```

After kill switch is active, new actions from that agent are denied.

## Typical operator flow

1. Watch events with `faramesh audit tail`
2. Find `approval_id` / pending action context
3. Inspect status with `faramesh approvals show <approval-id>`
4. Approve or deny with `faramesh approvals approve|deny <approval-id>`
5. Use `faramesh explain approval <approval-id>` or `faramesh explain <action-id>` for investigation when needed
