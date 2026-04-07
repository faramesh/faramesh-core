# LangChain Quick Guide

This guide shows the fastest way to run LangChain agents with Faramesh.

## Before you start

1. You have a working LangChain agent command.
2. You have Faramesh installed.
3. You have a policy file (start with `examples/starter.fpl`).

## What you get

- Every tool call is checked by policy before it runs.
- You can watch permit/deny/defer decisions live.
- You can keep your current agent code and command.

## What success looks like

When it works, you should see decision lines in `faramesh audit tail` while your agent runs tools.

Example shape:

- `PERMIT ...`
- `DENY ...`
- `DEFER ...`

## 1) Start fast

```bash
faramesh run -- python your_langchain_agent.py
```

Use your normal command after `faramesh run --`.

## 2) Watch decisions

```bash
faramesh audit tail
```

## 3) Validate policy

```bash
faramesh policy validate examples/starter.fpl
```

If validation fails, fix policy first before production tests.

## 4) If your LangChain flow also calls MCP tools

Wrap the MCP server too:

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

This keeps MCP tool calls inside the same governance boundary.

## Simple rollout pattern

1. Run one small agent task and watch decisions.
2. Add one strict rule for a risky tool.
3. Re-run the same task and confirm expected behavior.
4. Move to longer workload tests.

## Common problems

1. If all calls are blocked: check the policy and tool names.
2. If no decisions appear: check you started with `faramesh run -- ...`.
3. If MCP calls bypass policy: route MCP through `faramesh mcp wrap` or MCP HTTP gateway.

## Need deep internals?

Use power-user spec:

- `../../power-users/frameworks/LANGCHAIN_TECHNICAL_GUIDE.md`
