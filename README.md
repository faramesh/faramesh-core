<p align="center">
  <a href="https://faramesh.dev">Website</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/blog">Blog</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/docs">Documentation</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/changelog">Changelog</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/stack">Stack</a>
</p>

<p align="center">
  <img src="logo.png" alt="Faramesh" width="220" />
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Elastic%202.0-orange.svg" alt="License" /></a>
  <a href="https://pypi.org/project/faramesh/"><img src="https://img.shields.io/pypi/v/faramesh.svg" alt="PyPI version" /></a>
  <a href="https://github.com/faramesh/faramesh-core/actions"><img src="https://github.com/faramesh/faramesh-core/workflows/CI/badge.svg" alt="CI" /></a>
</p>

---

Faramesh is a tool for enforcing execution authorization on AI agents.

An agent action is any tool call, API invocation, database query, or external side effect that an autonomous agent attempts to perform. Faramesh provides a unified, non-bypassable gate between what the agent wants to do and what actually executes. It enforces policy-as-code at runtime and emits a deterministic, hash-verified decision record for every single action.

Modern AI agents decide on their own when to call tools, access production systems, or trigger real-world operations. There is still no standard way to answer *"Should this specific action be allowed right now?"* before any code runs. Every team ends up writing the same custom approval and audit logic from scratch. This is where Faramesh steps in.

**Key features:**

| | |
|---|---|
| **Policy-as-Code Enforcement** | Define exactly what agents are allowed to do in a single `policy.yaml` that lives in git. `faramesh policy-test` runs in CI and fails PRs that add unauthorized actions. One source of truth — versioned, reviewed, and enforced at runtime. |
| **Runtime Execution Gate** | Every tool call passes through a deterministic Action Authorization Boundary before execution. Returns `ALLOW`, `DENY`, or `PENDING` (human approval). Fail-closed by default — no match means denied. Works with LangChain, CrewAI, AutoGen, MCP, and any custom tool. |
| **Tamper-Evident Decision Log** | Every authorization decision is recorded with a canonical request hash, policy version hash, and outcome reason code. Full audit trail — no more guessing from traces. |
| **Agent Profiles** | Scope what tools and operations each agent is permitted to even attempt, before the policy engine runs. Per-agent allow-lists enforce least-privilege at the identity layer. |
| **CLI-First Management** | `faramesh serve`, `faramesh approve <id>`, `faramesh deny <id>`, `faramesh policy-diff`, live metrics, and native OpenTelemetry export. Drop-in wrapper: one line of code around any `@tool` decorator or MCP server. |

For more information, refer to the [What is Faramesh?](https://faramesh.dev/docs) page on the Faramesh website.

---

## Getting Started

**Install and run in 30 seconds:**

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

# Any custom tool or MCP server
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

Every tool call OpenClaw makes is then governed by Faramesh automatically — no code changes to your agent.

---

## Docker

```bash
docker compose up
```

---

## Documentation

| File | Contents |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step setup, SDK examples, CLI reference |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the execution gate works |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](CHANGELOG.md) | What changed |
| [policies/examples/](policies/examples/) | Ready-to-use policy examples |

Full documentation: [faramesh.dev/docs](https://faramesh.dev/docs)

---

> **Faramesh Core** is the open-source engine. [**Faramesh Horizon**](https://faramesh.dev) is the managed cloud version — credential sequestration, multi-tenant governance, signed DPR chains, and no deployment required.
