# Deep Agents Quick Guide

This guide shows the fastest way to run Deep Agents with Faramesh.

## Before you start

1. You can run your Deep Agents command locally.
2. You have Faramesh installed and a policy file.
3. You know where your high-risk tools are (for stricter rules).

## What you get

- Agent actions are policy-checked before execution.
- Delegation still stays under governance.
- You can monitor all decisions in one stream.

## What success looks like

Your deep-agent workflow runs, and you can see policy decisions for tool actions while tasks execute.

## 1) Run Deep Agents with Faramesh

```bash
faramesh run -- python -m deep_agents.main
```

Replace with your exact Deep Agents command if different.

## 2) Watch decisions

```bash
faramesh audit tail
```

## 3) Validate policy

```bash
faramesh policy validate examples/starter.fpl
```

Start simple, then tighten rules for sensitive tools.

## 4) If Deep Agents uses MCP tools

Wrap MCP servers:

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

This keeps delegated MCP calls inside governance.

## Simple rollout pattern

1. Run one short task and verify decisions.
2. Test delegated/sub-agent paths.
3. Add stricter policy for risky operations.
4. Re-test to confirm expected deny/defer behavior.

## Common problems

1. If tool calls are missing: run the app through `faramesh run`.
2. If decisions are mostly DENY: tighten or adjust policy rules.
3. If MCP tools are out of scope: route MCP through Faramesh boundary.

## Need deep internals?

Use power-user spec:

- [DEEP_AGENTS_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/DEEP_AGENTS_TECHNICAL_GUIDE.md)
