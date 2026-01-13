# FaraCore Integration Guide

Complete guide for integrating FaraCore v0.2 features into your AI agent workflows.

## Table of Contents

1. [Quick Integration Checklist](#quick-integration-checklist)
2. [Risk Scoring Integration](#risk-scoring-integration)
3. [Event Timeline Integration](#event-timeline-integration)
4. [UI Integration](#ui-integration)
5. [CLI Integration](#cli-integration)
6. [LangChain Integration](#langchain-integration)
7. [Docker Integration](#docker-integration)
8. [Testing Your Integration](#testing-your-integration)

## Quick Integration Checklist

- [ ] Install FaraCore: `pip install -e .`
- [ ] Configure policy with risk rules
- [ ] Start server: `faracore serve`
- [ ] Integrate SDK into agent code
- [ ] Test with sample actions
- [ ] Verify events are created
- [ ] Check UI displays correctly
- [ ] Test CLI commands

## Risk Scoring Integration

### 1. Add Risk Rules to Policy

Edit `policies/default.yaml`:

```yaml
risk:
  rules:
    - name: dangerous_shell
      when:
        tool: shell
        operation: run
        pattern: "rm -rf|shutdown|reboot"
      risk_level: high
    
    - name: large_payments
      when:
        tool: stripe
        operation: refund
        amount_gt: 1000
      risk_level: medium
```

### 2. Check Risk Level in Code

```python
from faracore.sdk.client import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")

action = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "rm -rf /tmp"},
    context={"agent_id": "my-agent"}
)

risk_level = action.get('risk_level')
print(f"Risk Level: {risk_level}")  # Will be "high"

# High risk actions automatically require approval
if risk_level == "high":
    print("High risk - approval required")
```

### 3. Display in UI

Risk levels are automatically displayed in:
- Action table (CLI: `faracore list`)
- Action details (CLI: `faracore get <id>`)
- Web UI action detail drawer

## Event Timeline Integration

### 1. Events Are Automatic

Events are automatically created when actions change state:
- `created` - When action is submitted
- `decision_made` - When policy evaluation completes
- `approved` / `denied` - When human makes decision
- `started` - When execution begins
- `succeeded` / `failed` - When execution completes

### 2. Access Events via API

```python
import requests

action_id = "your-action-id"
response = requests.get(f"http://127.0.0.1:8000/v1/actions/{action_id}/events")
events = response.json()

for event in events:
    print(f"{event['created_at']}: {event['event_type']}")
    print(f"  Meta: {event['meta']}")
```

### 3. Access Events via CLI

```bash
# View event timeline
faracore events <action-id>

# JSON output
faracore events <action-id> --json
```

### 4. Access Events via UI

1. Open action detail drawer (click action row)
2. Scroll to "Event Timeline" section
3. See all events with timestamps and metadata

## UI Integration

### Features Available in UI

1. **Risk Level Display**
   - Shown in action detail drawer
   - Color-coded by level (if you add custom styling)

2. **Event Timeline**
   - Automatically loaded when viewing action details
   - Shows all state transitions
   - Includes metadata for each event

3. **Demo Badge**
   - Automatically shown for actions with `agent_id="demo"` or `context.demo=true`
   - Yellow badge in action table and detail drawer

4. **Copy Curl Buttons**
   - One-click copy of approve/deny/start curl commands
   - Available in action detail drawer

### Customizing UI

The UI is built with React/TypeScript. To customize:

1. Edit `web/src/components/ActionDetails.tsx` for detail drawer
2. Edit `web/src/components/ActionTable.tsx` for table view
3. Rebuild: `cd web && npm run build`

## CLI Integration

### All Features Available in CLI

1. **Risk Level in List**
   ```bash
   faracore list
   # Shows: ID | Status | Risk | Tool | Operation | Params | Created
   ```

2. **Risk Level in Get**
   ```bash
   faracore get <id>
   # Shows risk_level field
   ```

3. **Event Timeline**
   ```bash
   faracore events <id>
   # Pretty-printed timeline
   ```

4. **Prefix Matching**
   ```bash
   # All commands support 8+ char prefixes
   faracore get 2755d4a8
   faracore events 2755d4a8
   faracore approve 2755d4a8
   ```

### CLI Output Examples

**List with Risk:**
```
Actions (5)
┌────────────┬──────────────────┬────────┬────────────┬──────────────┬──────────────────────────────────────┬─────────────────────┐
│ ID         │ Status           │ Risk   │ Tool       │ Operation    │ Params                               │ Created             │
├────────────┼──────────────────┼────────┼────────────┼──────────────┼──────────────────────────────────────┼─────────────────────┤
│ 2755d4a8   │ pending_approval │ high   │ shell     │ run         │ {"cmd": "rm -rf /tmp"}               │ 2026-01-12 10:00:00 │
│ a1b2c3d4   │ allowed          │ low    │ http      │ get         │ {"url": "https://..."}                │ 2026-01-12 09:59:00 │
└────────────┴──────────────────┴────────┴────────────┴──────────────┴──────────────────────────────────────┴─────────────────────┘
```

**Event Timeline:**
```
Event Timeline - 2755d4a8
┌─────────────────────┬──────────────────────┬─────────────────────────────┐
│ Time                │ Event                │ Details                     │
├─────────────────────┼──────────────────────┼─────────────────────────────┤
│ 2026-01-12 10:00:00 │ created              │ {"decision": "require_..."} │
│ 2026-01-12 10:00:01 │ decision_made        │ {"decision": "require_..."} │
│ 2026-01-12 10:05:23 │ approved             │ {"reason": "Looks safe"}   │
└─────────────────────┴──────────────────────┴─────────────────────────────┘
```

## LangChain Integration

### Basic Setup

```python
from langchain.tools import ShellTool
from faracore.sdk.client import ExecutionGovernorClient
from faracore.integrations.langchain.governed_tool import GovernedTool

# Initialize
client = ExecutionGovernorClient("http://127.0.0.1:8000")
shell_tool = ShellTool()

# Wrap with governance
governed = GovernedTool(
    tool=shell_tool,
    client=client,
    agent_id="my-langchain-agent"
)

# Use in agent
result = governed.run("ls -la")
```

### With Agent

```python
from langchain.agents import initialize_agent, AgentType

# Wrap all tools
governed_tools = [
    GovernedTool(tool=t, client=client, agent_id="agent-1")
    for t in [shell_tool, http_tool]
]

# Create agent
agent = initialize_agent(
    tools=governed_tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
)

# All tool calls are now governed
response = agent.run("List files and fetch a URL")
```

### How It Works

1. Tool call intercepted
2. Submitted to FaraCore
3. Policy evaluated + risk computed
4. If pending approval, polls until resolved
5. Executes only if allowed/approved
6. Reports result back

## Docker Integration

### Quick Start

```bash
# Start with demo data
docker compose up

# Access UI
open http://localhost:8000
```

### Custom Configuration

Edit `docker-compose.yaml`:

```yaml
services:
  faracore:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FARACORE_DEMO=1          # Seed demo data
      - FARACORE_ENABLE_CORS=1    # Enable CORS
      - FARACORE_HOST=0.0.0.0     # Bind address
      - FARACORE_PORT=8000        # Port
      - FARA_POLICY_FILE=/app/policies/custom.yaml
    volumes:
      - ./policies:/app/policies  # Mount custom policies
      - ./data:/app/data          # Persist data
```

### Build Custom Image

```bash
docker build -t my-faracore .
docker run -p 8000:8000 \
  -e FARACORE_DEMO=1 \
  -v $(pwd)/policies:/app/policies \
  my-faracore
```

## Testing Your Integration

### 1. Test Risk Scoring

```python
# Submit high-risk action
action = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "rm -rf /tmp"},
    context={"agent_id": "test"}
)

assert action['risk_level'] == 'high'
assert action['status'] == 'pending_approval'  # High risk auto-requires approval
```

### 2. Test Event Timeline

```python
# Submit action
action = client.submit_action(...)

# Get events
events = requests.get(f"{api_base}/v1/actions/{action['id']}/events").json()

# Verify events exist
assert len(events) > 0
assert events[0]['event_type'] == 'created'
```

### 3. Test UI

1. Start server: `faracore serve`
2. Open `http://127.0.0.1:8000`
3. Submit action via SDK
4. Verify:
   - Action appears in table
   - Risk level displayed
   - Event timeline shows events
   - Demo badge appears (if demo action)

### 4. Test CLI

```bash
# List actions
faracore list
# Verify risk column appears

# Get action
faracore get <id>
# Verify risk_level field

# View events
faracore events <id>
# Verify timeline displayed
```

### 5. Test LangChain

```python
# Wrap tool
governed = GovernedTool(tool=shell_tool, client=client, agent_id="test")

# Run (should be governed)
try:
    result = governed.run("echo test")
    print(f"Result: {result}")
except PermissionError as e:
    print(f"Denied: {e}")
```

## Troubleshooting

### Events Not Showing

- **Old actions**: Actions created before v0.2 don't have events
- **Server restart**: Restart server to ensure latest code
- **Check API**: `curl http://127.0.0.1:8000/v1/actions/{id}/events`

### Risk Level Always "low"

- Check policy has risk rules defined
- Verify risk rule conditions match your actions
- Check policy file is loaded: `faracore policy-validate policies/default.yaml`

### UI Not Updating

- Check SSE connection (browser console)
- Verify server is running latest code
- Clear browser cache

### CLI Not Showing Risk

- Update FaraCore: `pip install -e . --upgrade`
- Check action has risk_level: `faracore get <id> --json`

## Next Steps

1. **Customize Policy**: Add risk rules for your use case
2. **Integrate SDK**: Add to your agent code
3. **Monitor Actions**: Use UI or CLI to review actions
4. **Set Up Alerts**: Monitor high-risk actions
5. **Scale**: Use PostgreSQL for production

For more details, see the [main README](README.md).
