# LangGraph Quick Guide

This guide shows the fastest way to run LangGraph agents with Faramesh.

## Before you start

1. You have a LangGraph app command that runs locally.
2. You have Faramesh installed.
3. You have a policy file (for example `examples/starter.fpl`).

## What you get

- Tool calls are checked by policy first.
- You get a real-time decision stream.
- You keep your current LangGraph app command.

## What success looks like

You run your normal graph command, and you see governance decisions while graph nodes call tools.

## 1) Run your LangGraph app with governance

```bash
faramesh run -- python your_langgraph_app.py
```

Put your normal LangGraph command after `faramesh run --`.

## 2) Watch decisions live

```bash
faramesh audit tail
```

## 3) Check policy file quickly

```bash
faramesh policy validate examples/starter.fpl
```

Do this before every major policy change.

## 4) If LangGraph nodes call MCP tools

Use an MCP boundary:

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

This prevents MCP tools from bypassing governance.

## Simple rollout pattern

1. Test one graph path first.
2. Confirm decisions match expected policy behavior.
3. Test alternate graph branches and tool paths.
4. Keep audit output during load tests.

## Common problems

1. If expected tool calls do not show in audit: confirm the app is started through `faramesh run`.
2. If calls are denied: inspect policy match rules.
3. If MCP tools are not governed: ensure MCP traffic is routed through Faramesh.

## Need deep internals?

Use power-user spec:

- [LANGGRAPH_TECHNICAL_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/frameworks/LANGGRAPH_TECHNICAL_GUIDE.md)
