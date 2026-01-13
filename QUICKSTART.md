# FaraCore Quick Start

## Installation

```bash
cd fara-core
pip install -e .

# Optional: Install CLI enhancements for better output
pip install -e ".[cli]"
```

## Initialize Project

```bash
# Scaffold starter layout (creates policies/ and .env.example)
faracore init

# Review and customize policies/default.yaml
# Copy .env.example to .env if needed
```

## Start the Server

```bash
# Basic start
faracore serve

# With policy hot-reload (auto-reloads policy on file changes)
faracore serve --hot-reload
# Or use environment variable:
# FARACORE_HOT_RELOAD=1 faracore serve

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

```python
from faracore.sdk import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")

response = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "echo 'Hello FaraCore'"},
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
faracore list
faracore list --full  # Show full UUIDs
faracore list --json  # JSON output

# Get specific action (supports prefix matching)
faracore get 2755d4a8
faracore get 2755d4a8 --json

# Explain why action was allowed/denied
faracore explain 2755d4a8

# View event timeline
faracore events 2755d4a8

# Approve/deny action (supports prefix matching)
faracore approve 2755d4a8
faracore deny 2755d4a8
# Aliases:
faracore allow 2755d4a8  # Same as approve

# Replay an action
faracore replay 2755d4a8

# Get curl commands
faracore curl 2755d4a8

# Stream live actions (SSE)
faracore tail
```

### 5. DX Commands

```bash
# Initialize project structure
faracore init

# Build web UI
faracore build-ui

# Check environment
faracore doctor

# Compare policies
faracore policy-diff old.yaml new.yaml

# Generate Docker setup
faracore init-docker
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
faracore policy-refresh
```

## Event Timeline

View the complete event history for any action:

```bash
faracore events <action-id>
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
FARACORE_DEMO=1 faracore serve
```

This seeds the database with 5 sample actions if empty, making the UI immediately useful for demos.

## Docker Quick Start

```bash
docker compose up
```

Access UI at http://localhost:8000

## LangChain Integration

See `examples/langchain/` for how to wrap LangChain tools with FaraCore governance.

## DX Commands

FaraCore includes powerful developer experience commands:

```bash
# Initialize project structure
faracore init

# Check your environment
faracore doctor

# Explain why action was allowed/denied
faracore explain <action-id>

# Build web UI
faracore build-ui

# Compare policy files
faracore policy-diff old.yaml new.yaml

# Generate Docker setup
faracore init-docker

# Start server with policy hot-reload
faracore serve --watch

# Stream live actions
faracore tail

# Replay an action
faracore replay <action-id>
```

See [DX_FEATURES.md](DX_FEATURES.md) for complete documentation.

## Next Steps

1. Customize `policies/default.yaml` for your use case
2. Add risk scoring rules to your policy
3. Integrate the SDK into your agent code
4. Use LangChain integration for governed tool calls
5. Use the UI to monitor and approve actions
6. Check `/metrics` for Prometheus metrics
7. View event timelines for audit trails
8. Use `faracore doctor` to verify your setup
9. Use `faracore explain` to understand policy decisions

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
- Run `faracore policy-refresh`
- Check policy YAML syntax
