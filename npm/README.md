# faramesh

AI agent execution control. Policy-driven governance for every tool call.

## Install

```bash
npx @faramesh/cli@latest init
```

Or install globally:

```bash
npm install -g @faramesh/cli
```

## What it does

Faramesh sits between your AI agent and the tools it calls. Every tool call is checked against your policy before it runs.

- **Permit** — the rule said yes, the action runs
- **Deny** — blocked, nothing runs, the agent is told why
- **Defer** — held for a human to approve or deny

## Quick start

```bash
faramesh run python agent.py
```

## Learn more

- [Documentation](https://faramesh.dev/docs)
- [GitHub](https://github.com/faramesh/faramesh-core)
