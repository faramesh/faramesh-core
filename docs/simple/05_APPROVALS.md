# Approvals (DEFER)

When a rule returns `defer`, Faramesh pauses the action and waits for a human decision.

## Approve action

```bash
faramesh agent approve <defer-token>
```

## Deny action

```bash
faramesh agent deny <defer-token>
```

## Kill switch for an agent

```bash
faramesh agent kill <agent-id>
```

After kill switch is active, new actions from that agent are denied.

## Typical operator flow

1. Watch events with `faramesh audit tail`
2. Find `defer_token`
3. Approve or deny
4. Use `faramesh explain` for investigation when needed
