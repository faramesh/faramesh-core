# faramesh

AI agent execution control. Policy-driven governance for every tool call.

Faramesh helps teams implement deterministic AI governance for AI agents, MCP tool-calling,
and policy-as-code enforcement before execution.

## Install

```bash
npx @faramesh/cli@latest setup flow
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

## Common use cases

- AI agent governance for production tool-calling systems
- AI execution control for MCP servers and agentic workflows
- Policy-as-code guardrails for payments, infrastructure, and data operations
- Audit and compliance evidence for governed agent actions

## Quick start

```bash
faramesh setup flow
```

## Learn more

- [Documentation](https://faramesh.dev/docs)
- [GitHub](https://github.com/faramesh/faramesh-core)
- [Docs Index](../docs/README.md)
- [FPL Language Repository](https://github.com/faramesh/fpl-lang)
- [FPL Getting Started](https://github.com/faramesh/fpl-lang/blob/main/docs/GETTING_STARTED.md)
