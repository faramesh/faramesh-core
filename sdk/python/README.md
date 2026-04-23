# Faramesh Python SDK

Production-ready Python client for the Faramesh Execution Governor API.

For AI governance and AI execution control architecture details, see:

- [Faramesh Core README](../../README.md)
- [Core Docs Index](../../docs/README.md)
- [FPL Language README](https://github.com/faramesh/fpl-lang)
- [FPL Comparison](https://github.com/faramesh/fpl-lang/blob/main/docs/COMPARISON.md)

## Installation

```bash
pip install faramesh-sdk
```

Or install from source:

```bash
git clone https://github.com/faramesh/faramesh-python-sdk.git
cd faramesh-python-sdk
pip install -e .
```

## Quick Start

```python
from faramesh import configure, submit_action, approve_action

# Configure SDK (optional - defaults to http://127.0.0.1:8000)
configure(
    base_url="http://localhost:8000",
    token="your-token",  # Optional, can also use FARAMESH_TOKEN env var
)

# Submit an action
action = submit_action(
    agent_id="my-agent",
    tool="http",
    operation="get",
    params={"url": "https://example.com"}
)

print(f"Action {action.id} status: {action.status}")

# If action requires approval
if action.status == "pending_approval":
    approved = approve_action(
        action.id,
        action.approval_token,
        reason="Looks safe"
    )
    print(f"Action approved: {approved.status}")
```

## Features

- **Simple API**: Easy-to-use functions for all API operations
- **Batch Operations**: Submit multiple actions at once
- **Submit and Wait**: Automatically wait for action completion
- **Policy Building**: Build policies in Python code
- **Deterministic Hashing**: Client-side request_hash computation
- **Gate Endpoint**: Pre-check decisions without creating actions
- **Replay Helpers**: Verify decision determinism
- **Error Handling**: Typed exceptions for all error cases

## LangChain Drop-In Interception

Use this when you want explicit pre-execution governance for LangChain/LangGraph
tool calls directly in agent code.

```python
from faramesh.adapters.langchain import install_langchain_interceptor

install_langchain_interceptor(
    policy="policy.fpl",
    agent_id="support-agent",
    fail_open=False,
    include_langgraph=True,
)

# Build and run your LangChain/LangGraph agent normally.
```

What it intercepts before execution:

- LangChain `BaseTool.invoke`
- LangChain `BaseTool.ainvoke`
- LangChain `BaseTool.run`
- LangChain `BaseTool.arun`
- LangGraph `ToolNode._execute_tool_sync` (primary)
- LangGraph `ToolNode._execute_tool_async` (primary)
- LangGraph `ToolNode._run_one` (fallback for older ToolNode versions)
- LangGraph `ToolNode._arun_one` (fallback for older ToolNode versions)

## DeepAgents Drop-In Interception

Use this when your agent is assembled via `deepagents.create_deep_agent(...)`
and you want the same Faramesh governance guarantees.

```python
from faramesh.adapters.deepagents import install_deepagents_interceptor

install_deepagents_interceptor(
    policy="policy.fpl",
    agent_id="research-supervisor",
    fail_open=False,
    include_langgraph=True,
)

# Build and run your DeepAgents graph normally.
```

DeepAgents adapter guarantees:

- Patches DeepAgents `create_deep_agent` entrypoint
- Reuses LangChain/LangGraph execution-layer interception
- Preserves Faramesh fail-closed behavior (`PERMIT|DENY|DEFER`)
- Keeps tool IDs compatible with operation-aware FPL matching

### OpenRouter Qwen Production Harness (DeepAgents)

Use the bundled harness to validate production-style governance with
OpenRouter `qwen/qwen3.6-plus:free`.

```bash
# 1) Activate your SDK/deepagents environment
source /tmp/faramesh-deepagents-venv313/bin/activate

# 2) Start daemon with strict policy for this harness
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
go run ./cmd/faramesh serve \
    --socket /tmp/faramesh.sock \
    --data-dir /tmp/faramesh-data \
    --policy sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl

# 3) In another shell, run the harness under Faramesh runtime wiring
cd /Users/xquark_home/Faramesh-Nexus/faramesh-core
OPENROUTER_API_KEY=<your_key> \
go run ./cmd/faramesh run \
    --daemon-socket /tmp/faramesh.sock \
    --agent-id deepagents-openrouter-qwen-prod \
    --policy sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl \
    -- python sdk/python/examples/deepagents_openrouter_qwen_production.py

# 4) Export DPR evidence for the run
go run ./cmd/faramesh audit export \
    /tmp/faramesh-data/faramesh.db \
    --agent deepagents-openrouter-qwen-prod \
    --format json
```

Harness path: `sdk/python/examples/deepagents_openrouter_qwen_production.py`
Policy path: `sdk/python/examples/policies/deepagents_openrouter_qwen_production.fpl`

## One-Command Runtime For Custom Agents

For custom LangChain/LangGraph projects, use the daemon + runtime wrapper path:

```bash
# 1) Start governance daemon (strict preflight recommended)
faramesh serve --policy policies/agent.fpl --strict-preflight

# 2) Run any Python agent under governance
faramesh run --broker --agent-id my-agent -- python your_agent.py

# Module form also works
faramesh run --broker --agent-id my-agent -- python -m your_package.agent
```

How this works with one command:

1. `faramesh run` injects `FARAMESH_AUTOLOAD=1` so startup hooks activate.
2. Python `sitecustomize.py` loads Faramesh autopatch at interpreter startup.
3. Autopatch intercepts LangChain/LangGraph tool dispatch points before execution.
4. Every tool call is gated through daemon socket governance (`PERMIT|DENY|DEFER`).
5. `faramesh run` also wires `FARAMESH_SOCKET` and `FARAMESH_AGENT_ID` into child env
    (with explicit `--agent-id` override, otherwise inferred from command).

This makes interception resilient across many custom agent layouts without editing
agent source.

## Secret Shielding Model (State-Of-The-Art)

Goal: keep raw secrets out of LLM/agent process memory whenever possible.

Recommended boundary model:

1. Use `faramesh run --broker` so ambient API keys are stripped from child env.
2. Keep high-risk tools default-deny, and require explicit permit/defer policy rules.
3. Use brokered credentials (Vault/AWS/GCP/Azure) on daemon side.
4. Prefer out-of-process credentialed executors (proxy/MCP sidecar/service wrapper)
    so the agent sends intent/parameters, not secrets.
5. Verify evidence chain after runs (`faramesh audit verify ...`).

Concrete key-intake workflow:

```bash
# Provision local Vault and securely prompt for key value
faramesh credential vault up
faramesh credential vault put stripe/refund

# Start daemon with Vault backend, then run agent with stripped ambient keys
source ~/.faramesh/local-vault/vault.env
faramesh serve --policy policies/agent.fpl --vault-addr "$FARAMESH_CREDENTIAL_VAULT_ADDR" --vault-token "$FARAMESH_CREDENTIAL_VAULT_TOKEN" --vault-mount secret
faramesh run --broker --agent-id my-agent -- python your_agent.py
```

Important limitation (applies to any framework):

- If a tool executes inside the same Python process and needs a raw API key,
  that key is in-process by definition.
- For strict separation and anti-hijack posture, move secret-using calls to
  controlled runtime boundaries outside agent process.

## Policy/FPL Verification Harness

Run the focused verification matrix for policy/FPL effect handling and
LangChain/LangGraph interception behavior:

```bash
python -m unittest \
    tests.test_langchain_policy_fpl_harness \
    tests.test_deepagents_policy_fpl_harness \
    tests.test_deepagents_adapter \
    tests.test_langchain_adapter \
    tests.test_langchain_live_integration
```

For a full SDK pass:

```bash
python -m unittest discover -s tests
```

For full daemon-backed end-to-end policy verification with real FPL assets,
run:

```bash
bash tests/langchain_single_agent_real_stack_fpl.sh
```

This harness validates PERMIT, DENY, and DEFER flows against durable records.

## Premium Deployment Guidance

Use this checklist in CI/CD for production-grade LangChain/LangGraph governance:

1. Run deterministic policy/FPL harness tests on every pull request.
2. Run live integration tests (real langchain-core/langgraph) on mainline merges.
3. Keep `fail_open=False` in production unless you explicitly accept fail-open risk.
4. Pin and review framework versions whenever upgrading LangChain/LangGraph.
5. Run daemon-backed FPL verification before release cutovers.
6. Store test artifacts (logs and DPR records) for incident forensics.

For DeepAgents workloads, apply the same checklist plus DeepAgents adapter
coverage tests (`tests.test_deepagents_adapter`,
`tests.test_deepagents_policy_fpl_harness`).

Note: Python 3.14 currently emits a LangChain core Pydantic v1 compatibility
warning in test output; test execution still completes successfully.

## Gate Endpoint & Deterministic Hashing

The SDK provides helpers for deterministic decision verification:

### Compute Request Hash Locally

```python
from faramesh import compute_request_hash

payload = {
    "agent_id": "my-agent",
    "tool": "http",
    "operation": "get",
    "params": {"url": "https://example.com"},
    "context": {}
}

# Compute hash locally (matches server's request_hash)
hash_value = compute_request_hash(payload)
print(f"Request hash: {hash_value}")
```

### Gate Decide (Decision Only)

```python
from faramesh import gate_decide

# Get decision without creating an action
decision = gate_decide(
    agent_id="my-agent",
    tool="http",
    operation="get",
    params={"url": "https://example.com"}
)

if decision.outcome == "EXECUTE":
    print("Action would be allowed")
elif decision.outcome == "HALT":
    print(f"Action would be denied: {decision.reason_code}")
else:  # ABSTAIN
    print("Action requires approval")
```

### Execute If Allowed (Gated Execution)

```python
from faramesh import execute_if_allowed

def my_executor(tool, operation, params, context):
    # Your actual execution logic
    return {"status": "done"}

result = execute_if_allowed(
    agent_id="my-agent",
    tool="http",
    operation="get",
    params={"url": "https://example.com"},
    executor=my_executor
)

if result["executed"]:
    print("Action executed:", result["execution_result"])
else:
    print("Action blocked:", result["reason_code"])
```

### Replay Decision

```python
from faramesh import replay_decision

# Verify decision is deterministic
result = replay_decision(action_id="abc123")

if result.success:
    print("Decision replay passed!")
else:
    print("Mismatches:", result.mismatches)
```

## Documentation

Full documentation is available at: https://github.com/faramesh/faramesh-docs

See `docs/SDK-Python.md` for detailed API reference.

## Repository

**Source**: https://github.com/faramesh/faramesh-python-sdk

## License

Elastic License 2.0
