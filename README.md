<p align="center">
  <img src="logo.png" alt="Faramesh" width="220" />
</p>

<p align="center">
  <strong>Govern every AI agent action — one command, every framework, every platform.</strong>
</p>

<p align="center">
  <a href="https://faramesh.dev">Website</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/docs">Docs</a> &nbsp;·&nbsp;
  <a href="https://faramesh.dev/community">Community</a>
</p>

<p align="center">
  <a href="https://github.com/faramesh/faramesh-core/releases"><img src="https://img.shields.io/github/v/release/faramesh/faramesh-core?color=blue" alt="Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Elastic%202.0-orange.svg" alt="License" /></a>
  <a href="https://github.com/faramesh/faramesh-core/actions"><img src="https://github.com/faramesh/faramesh-core/workflows/CI/badge.svg" alt="CI" /></a>
</p>

---

Faramesh is a pre-execution governance engine for AI agents. It sits between every agent tool call and the real world — evaluating policy, recording decisions in a tamper-evident chain, and blocking or deferring dangerous actions before they execute.

One binary. Works with 13 frameworks. Runs on Linux, macOS, and Windows.

## See it in 30 seconds

```bash
# Install
brew install faramesh/tap/faramesh
# or: go install github.com/faramesh/faramesh-core/cmd/faramesh@latest

# Run the demo
faramesh demo
```

```
Faramesh — Unified Agent Governance

[10:00:15] PERMIT  get_exchange_rate      from=USD to=SEK              latency=11ms
[10:00:17] DENY    shell/run              cmd="rm -rf /"               scanner=SCANNER_DENY
[10:00:18] PERMIT  read_customer          id=cust_abc123               latency=9ms
[10:00:20] DEFER   stripe/refund          amount=$12,000               awaiting approval
[10:00:21] DENY    send_email             recipients=847               policy=deny-mass-email

5 actions evaluated. 2 PERMIT  2 DENY  1 DEFER
```

## How it works

### 1. Write a policy

```yaml
# policy.yaml
faramesh-version: '1.0'
agent-id: payment-bot
default_effect: permit

rules:
  - id: block-destructive-shell
    match:
      tool: shell/run
      when: 'args["cmd"] matches "rm\\s+-[rf]"'
    effect: deny

  - id: require-approval-high-refund
    match:
      tool: stripe/refund
      when: 'args["amount"] > 500'
    effect: defer
    reason: refund exceeds $500 — requires finance approval
```

### 2. Run your agent

```bash
faramesh run python agent.py
```

That's it. Faramesh detects the framework, patches tool dispatch, strips ambient credentials, sets up network interception, and reports what enforcement is active:

```
Faramesh Enforcement Report
  Runtime:     local
  Framework:   langchain

  ✓ Framework auto-patch (FARAMESH_AUTOLOAD)
  ✓ Credential broker (stripped: OPENAI_API_KEY, STRIPE_API_KEY)
  ✓ Network interception (proxy env vars)

  Trust level: PARTIAL
```

## Supported frameworks (auto-patched, zero code changes)

| Framework | Patch Point | Adapter |
|-----------|-------------|---------|
| LangGraph / LangChain | `BaseTool.run()` | auto-patch |
| CrewAI | `BaseTool._run()` | auto-patch |
| AutoGen / AG2 | `ConversableAgent._execute_tool_call()` | auto-patch |
| Pydantic AI | `Tool.run()` + `Agent._call_tool()` | auto-patch + adapter |
| Google ADK | `FunctionTool.call()` | auto-patch + adapter |
| LlamaIndex | `FunctionTool.call()` / `BaseTool.call()` | auto-patch + adapter |
| AWS Strands Agents | `Agent._run_tool()` | auto-patch + adapter |
| OpenAI Agents SDK | `FunctionTool.on_invoke_tool()` | auto-patch |
| Smolagents | `Tool.__call__()` | auto-patch |
| Haystack | `Pipeline.run()` | auto-patch |
| Deep Agents | LangGraph dispatch + `AgentMiddleware` | middleware |
| AWS Bedrock AgentCore | App middleware + Strands hook | adapter |
| MCP Servers (Node.js) | `tools/call` handler | auto-patch |

## Credential broker (6 backends)

Faramesh strips API keys from the agent's environment. The agent requests credentials through the broker at call time — if policy denies the action, the credential is never issued.

| Backend | Config |
|---------|--------|
| HashiCorp Vault | `--vault-addr`, `--vault-token` |
| AWS Secrets Manager | `--aws-secrets-region` |
| GCP Secret Manager | `--gcp-secrets-project` |
| Azure Key Vault | `--azure-vault-url`, `--azure-tenant-id` |
| 1Password Connect | `FARAMESH_CREDENTIAL_1PASSWORD_HOST` |
| Infisical | `FARAMESH_CREDENTIAL_INFISICAL_HOST` |

## Cross-platform enforcement

| Platform | Layers | Trust Level |
|----------|--------|-------------|
| **Linux + root** | seccomp-BPF + Landlock + netns + iptables + credential broker + auto-patch | STRONG |
| **Linux** | Landlock + proxy env vars + credential broker + auto-patch | MODERATE |
| **macOS** | Proxy env vars + PF rules (sudo) + credential broker + auto-patch | PARTIAL |
| **Windows** | Proxy env vars + WinDivert (admin) + credential broker + auto-patch | PARTIAL |
| **Serverless** | Credential broker + auto-patch | CREDENTIAL_ONLY |

`faramesh run` detects the OS and activates the strongest available enforcement automatically.

## SDK integration (optional — for deeper control)

```python
pip install faramesh
```

```python
from faramesh import govern

governed_refund = govern(stripe_refund, policy='payment.yaml', agent_id='payment-bot')

try:
    result = governed_refund(amount=100, currency='usd')
except DenyError as e:
    print(f"Blocked: {e.reason}")
except DeferredError as e:
    print(f"Awaiting approval: {e.defer_token}")
```

## CLI reference

```bash
faramesh run -- python agent.py        # Govern agent with full enforcement stack
faramesh serve --policy policy.yaml    # Start governance daemon
faramesh demo                          # See governance in action
faramesh init                          # Auto-detect env, generate config
faramesh detect                        # Print runtime/framework/harness detection

faramesh policy validate policy.yaml   # Validate and compile a policy
faramesh policy inspect policy.yaml    # Show compiled policy summary
faramesh policy diff a.yaml b.yaml     # Diff two policy files
faramesh policy backtest policy.yaml   # Replay policy against historical WAL

faramesh audit tail                    # Stream live decisions
faramesh audit verify faramesh.db      # Verify DPR chain integrity
faramesh compliance export             # Export evidence bundle

faramesh agent approve <token>         # Approve a DEFER
faramesh agent deny <token>            # Deny a DEFER
faramesh agent kill <agent-id>         # Kill switch
```

## Install

```bash
# Homebrew (macOS / Linux)
brew install faramesh/tap/faramesh

# Go toolchain
go install github.com/faramesh/faramesh-core/cmd/faramesh@latest

# Docker
docker run --rm ghcr.io/faramesh/faramesh:latest demo

# Python SDK
pip install faramesh

# Node.js SDK
npm install @faramesh/sdk
```

## Architecture

Every tool call flows through the same 11-step pipeline regardless of framework or adapter:

```
CanonicalActionRequest
 ├─[1] Kill switch check       (nanoseconds)
 ├─[2] Phase check             (is tool visible in this workflow phase?)
 ├─[3] Pre-execution scanners  (shell, secret, PII — parallel)
 ├─[4] Session state read      (counters + ring buffer)
 ├─[5] History ring read       (last N calls within T seconds)
 ├─[6] External selector fetch (lazy, parallel, cached)
 ├─[7] Policy evaluation       (expr-lang bytecode, ~1μs/rule)
 ├─[8] Decision                (PERMIT | DENY | DEFER | SHADOW)
 ├─[9] WAL write ───────────── fsync BEFORE returning decision
 ├─[10] Async replication      (SQLite DPR, session, metrics)
 └─[11] Return Decision
```

If step 9 (WAL write) fails, the decision is DENY. No execution without a durable audit record.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Elastic License 2.0](LICENSE). Free to use, modify, and distribute. Cannot be offered as a hosted service without a commercial agreement.
