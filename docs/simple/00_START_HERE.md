# Faramesh: Start Here

If you only read one file, read this one.

Faramesh is a policy guard for AI agent tool calls.
It decides:

- `PERMIT`: allow the tool call
- `DENY`: block the tool call
- `DEFER`: pause and wait for human approval

## Fast path (5 minutes)

1. Install/build Faramesh: see `01_INSTALL.md`
2. Create policy file: see `03_POLICY_SIMPLE.md`
3. Start daemon:

```bash
faramesh serve --policy policy.yaml
```

4. Watch live decisions:

```bash
faramesh audit tail
```

5. Test with built-in demo:

```bash
faramesh demo
```

## What users normally do

- Policy authors: write and validate policy files.
- Operators: run `faramesh serve`, tail decisions, verify chain.
- Approvers: approve or deny deferred actions.

## Core commands to remember

```bash
faramesh policy validate policy.yaml
faramesh serve --policy policy.yaml
faramesh audit tail
faramesh agent approve <defer-token>
faramesh agent deny <defer-token>
faramesh explain --last-deny
```

## Next files to read

- `01_INSTALL.md`
- `02_QUICKSTART.md`
- `03_POLICY_SIMPLE.md`
- `04_RUN_AND_MONITOR.md`
- `08_TROUBLESHOOTING.md`
