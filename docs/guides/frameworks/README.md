# Framework Guides (Quick Usage)

These guides are for fast, practical usage.

Use simple setup steps first. Move to power-user framework specs only when you need deep internals.

## Quick Framework Guides

1. `LANGCHAIN_QUICK_GUIDE.md`
2. `LANGGRAPH_QUICK_GUIDE.md`
3. `DEEP_AGENTS_QUICK_GUIDE.md`

## Which one should I open?

1. If your app is a LangChain app: `LANGCHAIN_QUICK_GUIDE.md`
2. If your app is graph-first LangGraph: `LANGGRAPH_QUICK_GUIDE.md`
3. If your app uses Deep Agents runtime: `DEEP_AGENTS_QUICK_GUIDE.md`

## What is common across all three?

1. Launch through `faramesh run -- ...`
2. Validate policy before rollout
3. Keep `faramesh audit tail` running during tests
4. Wrap MCP servers too if your stack uses MCP tools

## Power-User Framework Specs

- `../../power-users/frameworks/README.md`
