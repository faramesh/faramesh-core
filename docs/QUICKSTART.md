# Faramesh Quick Start

## Installation

```bash
cd faramesh-core
pip install -e .

# Optional: Install CLI enhancements for better output
pip install -e ".[cli]"
```

## Initialize Project

```bash
# Scaffold starter layout (creates policies/ and .env.example)
faramesh init

# Review and customize policies/default.yaml
# Copy .env.example to .env if needed
```

## Start the Server

```bash
# Basic start
faramesh serve

# With policy hot-reload (auto-reloads policy on file changes)
faramesh serve --hot-reload
# Or use environment variable:
# FARAMESH_HOT_RELOAD=1 faramesh serve

# Note: Hot reload only works for local policy files. If policy reload fails,
# the previous valid policy stays active to prevent service disruption.
```

The server will start on `http://127.0.0.1:8000`

## Access the UI

Open `http://127.0.0.1:8000` in your browser.

The UI features:
- **Dark Mode (default)** with brand colors
- **Light Mode** toggle in header
- **Action list table** with real-time updates
- **Filters** for status, agent, tool, and search
- **Action details modal** with approve/deny buttons
- **SSE live updates** for action status changes

## Test the Flow

### 1. Submit an Action (Python)

**Modern Functional API:**
```python
from faramesh import configure, submit_action

configure(base_url="http://127.0.0.1:8000")

response = submit_action(
    agent_id="test-agent",
    tool="shell",
    operation="run",
    params={"cmd": "echo 'Hello Faramesh'"}
)

print(f"Action ID: {response['id']}")
print(f"Status: {response['status']}")
```

**Class-based API (Alternative):**
```python
from faramesh.sdk.client import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")

response = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "echo 'Hello Faramesh'"},
    context={"agent_id": "test-agent"}
)

print(f"Action ID: {response['id']}")
print(f"Status: {response['status']}")
```

### 2. Submit an Action (cURL)

```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent",
    "tool": "shell",
    "operation": "run",
    "params": {"cmd": "echo test"}
  }'
```

### 3. View Actions in UI

1. Open `http://127.0.0.1:8000`
2. See the action appear in the table
3. Click the row to see details
4. If status is `pending_approval`, click Approve or Deny

### 4. Use CLI

```bash
# List actions (color-coded, shows risk levels)
faramesh list
faramesh list --full  # Show full UUIDs
faramesh list --json  # JSON output

# Get specific action (supports prefix matching)
faramesh get 2755d4a8
faramesh get 2755d4a8 --json

# Explain why action was allowed/denied
faramesh explain 2755d4a8

# View event timeline
faramesh events 2755d4a8

# Approve/deny action (supports prefix matching)
faramesh approve 2755d4a8
faramesh deny 2755d4a8
# Aliases:
faramesh allow 2755d4a8  # Same as approve

# Replay an action
faramesh replay 2755d4a8

# Get curl commands
faramesh curl 2755d4a8

# Stream live actions (SSE)
faramesh tail
```

### 5. DX Commands

```bash
# Initialize project structure
faramesh init

# Build web UI
faramesh build-ui

# Check environment
faramesh doctor

# Compare policies
faramesh policy-diff old.yaml new.yaml

# Generate Docker setup
faramesh init-docker
```

## Policy Configuration

Edit `policies/default.yaml` to customize rules:

```yaml
rules:
  - match:
      tool: "shell"
      op: "*"
    require_approval: true
    description: "Shell commands require approval"
    risk: "medium"

# Optional: Risk scoring rules
risk:
  rules:
    - name: dangerous_shell
      when:
        tool: shell
        operation: run
        pattern: "rm -rf"
      risk_level: high
```

Refresh policy:
```bash
faramesh policy-refresh
```

## Event Timeline

View the complete event history for any action:

```bash
faramesh events <action-id>
```

Or in the UI: Click any action row to see the event timeline in the detail drawer.

## Smoke Test

Run the included smoke test:

```bash
python3 test_smoke.py
```

This tests:
- Health endpoint
- Metrics endpoint
- Action submission
- Action retrieval
- Action listing
- Action approval

## Demo Mode

Start with demo data:

```bash
FARAMESH_DEMO=1 faramesh serve
```

This seeds the database with 5 sample actions if empty, making the UI immediately useful for demos.

## Docker Quick Start

```bash
docker compose up
```

Access UI at http://localhost:8000

## LangChain Integration

See `examples/langchain/` for how to wrap LangChain tools with Faramesh governance.

## DX Commands

Faramesh includes powerful developer experience commands:

```bash
# Initialize project structure
faramesh init

# Check your environment
faramesh doctor

# Explain why action was allowed/denied
faramesh explain <action-id>

# Build web UI
faramesh build-ui

# Compare policy files
faramesh policy-diff old.yaml new.yaml

# Generate Docker setup
faramesh init-docker

# Start server with policy hot-reload
faramesh serve --watch

# Stream live actions
faramesh tail

# Replay an action
faramesh replay <action-id>
```

See `docs/CLI.md` and `docs/Policies.md` for full DX and policy details.

## Next Steps

1. Customize `policies/default.yaml` for your use case
2. Add risk scoring rules to your policy
3. Integrate the SDK into your agent code
4. Use LangChain integration for governed tool calls
5. Use the UI to monitor and approve actions
6. Check `/metrics` for Prometheus metrics
7. View event timelines for audit trails
8. Use `faramesh doctor` to verify your setup
9. Use `faramesh explain` to understand policy decisions

## Troubleshooting

**Server won't start:**
- Check if port 8000 is available
- Install dependencies: `pip install -e .`

**Actions not showing:**
- Check browser console for errors
- Verify SSE connection in Network tab
- Check server logs

**Policy not working:**
- Verify `policies/default.yaml` exists
- Run `faramesh policy-refresh`
- Check policy YAML syntax
