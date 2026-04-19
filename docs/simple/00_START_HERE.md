# Faramesh: Start Here (CLI/DX 2.0)

If you only read one file, read this one.

Faramesh is a governance control surface for AI agent tool calls.
It decides:

- `PERMIT`: allow the tool call
- `DENY`: block the tool call
- `DEFER`: pause and wait for human approval

## Fast path (about 5 minutes)

1. Install/build Faramesh: see `01_INSTALL.md`
2. Create policy file: see `03_POLICY_SIMPLE.md`
3. Run guided first-run setup:

```bash
faramesh wizard first-run
```

4. Or run the explicit default path manually:

```bash
faramesh credential enable --policy policy.yaml
faramesh up --policy policy.yaml
```

5. Stream live decisions:

```bash
faramesh audit tail
```

6. Run your real agent through governance:

```bash
faramesh run --broker -- python your_agent.py
```

## Typical roles

- Policy authors: write and validate policy files.
- Operators: run `faramesh up`, stream decisions, resolve approvals, and verify evidence.
- Approvers: approve or deny deferred actions.

## Core commands to remember (default path)

```bash
faramesh up --policy policy.yaml
faramesh wizard first-run
faramesh status
faramesh credential enable --policy policy.yaml
faramesh run --broker -- python your_agent.py
faramesh approvals
faramesh approvals watch
faramesh approvals approve <approval-id>
faramesh audit tail
faramesh audit show <action-id>
faramesh explain <action-id>
faramesh explain approval <approval-id>
faramesh audit verify
faramesh policy validate policy.yaml
faramesh credential status
```

## Operator workflows (power path)

```bash
faramesh start --policy policy.yaml
faramesh serve --policy policy.yaml --metrics-port 9108
faramesh discover --cwd .
faramesh attach --cwd . --observation-window 30s
faramesh coverage
faramesh gaps
faramesh suggest --out suggested-policy.yaml
faramesh incident declare --agent my-agent --severity high --title "unexpected data egress"
faramesh identity status
faramesh identity verify --spiffe spiffe://example.org/agent/my-agent
```

## Next files to read

- `01_INSTALL.md`
- `02_QUICKSTART.md`
- `03_POLICY_SIMPLE.md`
- `04_RUN_AND_MONITOR.md`
- `08_TROUBLESHOOTING.md`
