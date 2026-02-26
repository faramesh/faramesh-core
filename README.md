# Faramesh Core

**Execution gatekeeper for AI agents — open source, self-hosted, zero infrastructure.**

Every tool call your agent makes passes through Faramesh before it runs. You write a policy file. Faramesh enforces it: allow, deny, or pause for human approval.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Elastic%202.0-orange.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/faramesh.svg)](https://pypi.org/project/faramesh/)
[![CI](https://github.com/faramesh/faramesh-core/workflows/CI/badge.svg)](https://github.com/faramesh/faramesh-core/actions)

---

## Install and run

```bash
pip install faramesh
faramesh serve
```

Open `http://localhost:8000` — the dashboard is live.

---

## Govern any agent framework

```python
from faramesh.integrations import govern

# LangChain
from langchain.tools import ShellTool
tool = govern(ShellTool(), agent_id="my-agent")

# CrewAI
from crewai_tools import FileReadTool
tool = govern(FileReadTool(), agent_id="my-agent")

# AutoGen
governed_fn = govern(my_function, agent_id="my-agent", framework="autogen")

# Any custom tool / MCP
tool = govern(my_tool, agent_id="my-agent")
```

That's it. Every call now routes through Faramesh before it executes.

---

## Write a policy

Edit `policies/default.yaml`:

```yaml
rules:
  - match:
      tool: shell
      op: "*"
    require_approval: true
    description: "Shell commands need a human to approve"

  - match:
      tool: http
      op: get
    allow: true

  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Deny everything else"
```

Rules are first-match-wins. No match = denied by default (fail-closed).

---

## How it works

```
Agent wants to run a tool
        ↓
Faramesh evaluates the policy
        ↓
   ┌────────────────────────────────────────┐
   │ ALLOW   → tool runs immediately        │
   │ DENY    → PermissionError raised       │
   │ PENDING → paused, you approve/deny     │
   │           in the dashboard or CLI      │
   └────────────────────────────────────────┘
```

Approve or deny from the web UI, CLI, or HTTP API:

```bash
faramesh approve <action-id>
faramesh deny <action-id>
```

---

## OpenClaw plugin

If you use [OpenClaw](https://github.com/OpenClaw/OpenClaw), install the plugin:

```bash
openclaw plugins install @faramesh/openclaw
```

Every tool call OpenClaw makes is then governed by Faramesh automatically, with no code changes to your agent.

---

## Docker

```bash
docker compose up
```

---

## Docs

| File | Contents |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step setup, SDK examples, CLI reference |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the execution gate works |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](CHANGELOG.md) | What changed |
| [policies/examples/](policies/examples/) | Ready-to-use policy examples |
| [policies/packs/](policies/packs/) | Policy packs for common scenarios (SaaS refunds, infra, etc.) |

---

> **Faramesh Core** is the open-source engine. [**Faramesh Horizon**](https://faramesh.dev) is the managed cloud version — no deployment, instant onboarding.
