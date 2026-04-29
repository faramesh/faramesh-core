# Faramesh Features (Quick Guide for All Users)

This page covers all major Faramesh features in simple words.

If you want deep technical details, use:

- [FEATURES_TECHNICAL_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/FEATURES_TECHNICAL_REFERENCE.md)

## Fast Start (3 commands)

```bash
faramesh run -- python your_agent.py
faramesh audit tail
faramesh policy validate examples/starter.fpl
```

What this gives you:

1. Your agent runs behind governance.
2. You can see live allow/block/defer decisions.
3. You know your policy file is valid before rollout.

## Observe-first rollout (recommended)

```bash
faramesh discover --source ./
faramesh attach --agent-id my-agent --cmd "python agent.py"
faramesh coverage --agent-id my-agent
faramesh gaps --agent-id my-agent
faramesh suggest --agent-id my-agent
```

Pack rollout controls:

```bash
faramesh pack status faramesh/<pack>
faramesh pack shadow faramesh/<pack>
faramesh pack enforce faramesh/<pack>
```

## How to use this page

Use the table below like a menu:

1. pick the feature you need
2. run the quick command
3. open the linked guide for a step-by-step walkthrough

You do not need to read everything to get started.

## Full Feature Map (Quick Path)

| Feature | What it does | Quick command | Learn more |
|---|---|---|---|
| Install | Installs Faramesh | `brew install faramesh/tap/faramesh` | [01_INSTALL.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/01_INSTALL.md) |
| Setup lifecycle | Guided first-run + runtime controls | `faramesh wizard first-run` | [00_START_HERE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/00_START_HERE.md) |
| Agent governance run | Checks every tool call by policy | `faramesh run -- python your_agent.py` | [02_QUICKSTART.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/02_QUICKSTART.md) |
| LangChain usage | Governs LangChain tool calls | `faramesh run -- python your_langchain_agent.py` | [LANGCHAIN_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGCHAIN_QUICK_GUIDE.md) |
| LangGraph usage | Governs LangGraph graph/tool actions | `faramesh run -- python your_langgraph_app.py` | [LANGGRAPH_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGGRAPH_QUICK_GUIDE.md) |
| Deep Agents usage | Governs deep-agent execution and delegation | `faramesh run -- python -m deep_agents.main` | [DEEP_AGENTS_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/DEEP_AGENTS_QUICK_GUIDE.md) |
| Policy writing (FPL) | Lets you define rules | `faramesh policy validate examples/starter.fpl` | [03_POLICY_SIMPLE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/03_POLICY_SIMPLE.md) |
| Live monitoring | Shows permit/deny/defer in real time | `faramesh audit tail` | [04_RUN_AND_MONITOR.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/04_RUN_AND_MONITOR.md) |
| Human approvals | Review and resolve deferred actions | `faramesh approvals` | [05_APPROVALS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/05_APPROVALS.md) |
| Action explain | Explain what happened for one governed action | `faramesh explain <action-id>` | [04_RUN_AND_MONITOR.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/04_RUN_AND_MONITOR.md) |
| MCP governance | Governs MCP `tools/call` | `faramesh mcp wrap -- node server.js` | [MCP_INTERCEPTION_GOVERNANCE_PLAN.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/MCP_INTERCEPTION_GOVERNANCE_PLAN.md) |
| Runtime adapters | Connects to common agent runtime paths | `faramesh run -- <your command>` | [06_ADAPTERS.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/06_ADAPTERS.md) |
| Production setup | Adds stronger controls | `faramesh onboard --policy policy.fpl` | [07_PRODUCTION_SETUP.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/07_PRODUCTION_SETUP.md) |
| Troubleshooting | Fixes common issues fast | `faramesh audit verify` | [08_TROUBLESHOOTING.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/08_TROUBLESHOOTING.md) |
| Credential broker | Keeps secrets away from agent env | `faramesh credential enable` | [Docs Index](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Workload identity | Uses SPIFFE identity checks | `faramesh identity status` | [Docs Index](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Observability | Exposes metrics endpoint | `faramesh serve --metrics-port 9090` | [Docs Index](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |
| Network hardening | Adds governed proxy and rollout controls | `faramesh serve --proxy-port 18080 --proxy-forward` | [NETWORK_HARDENING_CANARY_RUNBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/NETWORK_HARDENING_CANARY_RUNBOOK.md) |
| Chain exfil hardening | Tests and blocks cross-step exfil patterns | see runbook stages | [CHAIN_EXFIL_HARDENING_PLAYBOOK.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/CHAIN_EXFIL_HARDENING_PLAYBOOK.md) |
| SDK usage (Python/Node) | Adds governance calls in app code | import `govern()` / `GovernedTool` | [Docs Index](https://github.com/faramesh/faramesh-core/blob/main/docs/README.md) |

## Quick Usage by Popular Stack

### LangChain / LangGraph

```bash
faramesh run -- python your_agent.py
```

See dedicated guides:

- [LANGCHAIN_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGCHAIN_QUICK_GUIDE.md)
- [LANGGRAPH_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/LANGGRAPH_QUICK_GUIDE.md)

### Deep Agents

```bash
faramesh run -- python -m deep_agents.main
```

See dedicated guide:

- [DEEP_AGENTS_QUICK_GUIDE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/guides/frameworks/DEEP_AGENTS_QUICK_GUIDE.md)

### MCP agents (Claude Code, Cursor, others)

```bash
faramesh mcp wrap -- node your-mcp-server.js
```

### Existing repo integration

```bash
faramesh wizard first-run
```

## Simple first-day rollout plan

1. Start with `examples/starter.fpl`.
2. Run one real agent command through `faramesh run -- ...`.
3. Keep `faramesh audit tail` open and observe decisions.
4. Add one stricter rule for a high-risk tool.
5. Re-test and confirm expected permit/deny behavior.

## Production-ready checklist (simple version)

1. Policy validates cleanly.
2. Agent is always launched through Faramesh entrypoint.
3. Live monitoring is enabled for ops team.
4. High-risk tools have explicit deny/defer rules.
5. Team knows where quick guides and power-user docs live.

## Which docs should I read next?

1. If you are new: [Simple Docs Index](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/README.md)
2. If you are deploying to production: [07_PRODUCTION_SETUP.md](https://github.com/faramesh/faramesh-core/blob/main/docs/simple/07_PRODUCTION_SETUP.md)
3. If you need deep internals: [FEATURES_TECHNICAL_REFERENCE.md](https://github.com/faramesh/faramesh-core/blob/main/docs/power-users/FEATURES_TECHNICAL_REFERENCE.md)
