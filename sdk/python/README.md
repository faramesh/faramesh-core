# Faramesh Python SDK

Production-ready Python client for the Faramesh Execution Governor API.

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
