# FaraCore

**Governance and approval system for AI agent actions**

FaraCore provides policy-driven governance, risk scoring, and human-in-the-loop approval for AI agent tool calls. Built for production use with a modern web UI, comprehensive CLI, and SDK integrations.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

### 🎯 Core Capabilities

- **Policy-Driven Governance**: YAML-based policies with first-match-wins evaluation
- **Risk Scoring**: Automatic risk assessment (low/medium/high) based on configurable rules
- **Human-in-the-Loop**: Approval workflows for high-risk or policy-required actions
- **Audit Ledger**: Complete event timeline for every action (created, approved, executed, etc.)
- **Real-Time UI**: Modern web dashboard with live updates via Server-Sent Events
- **Developer-Friendly CLI**: Powerful command-line interface with prefix matching
- **SDK Integration**: Python and Node.js SDKs for easy agent integration
- **LangChain Support**: Drop-in wrapper for LangChain tools

### 🚀 Quick Start

```bash
# Install
pip install -e .

# Start server
faracore serve

# Access UI
open http://127.0.0.1:8000
```

### 📦 Docker Quick Start

```bash
# Start with demo data
docker compose up

# Access UI
open http://localhost:8000
```

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Policy Configuration](#policy-configuration)
- [Risk Scoring](#risk-scoring)
- [CLI Usage](#cli-usage)
- [Web UI](#web-ui)
- [SDK Integration](#sdk-integration)
- [LangChain Integration](#langchain-integration)
- [Docker Deployment](#docker-deployment)
- [API Reference](#api-reference)
- [Environment Variables](#environment-variables)
- [Examples](#examples)
- [Architecture](#architecture)
- [Contributing](#contributing)

## Installation

### Prerequisites

- Python 3.9+
- pip
- Node.js 18+ (optional, for UI development)

### Install from Source

```bash
git clone https://github.com/yourorg/faracore.git
cd faracore
pip install -e .
```

### Optional Dependencies

For enhanced CLI output and DX features:
```bash
pip install -e ".[cli]"
```

This installs:
- `rich` - Beautiful terminal output with colors
- `tabulate` - Professional table formatting
- `watchdog` - File watching (for `--watch` flag)
- `sseclient` - SSE streaming (for `tail` command)

**Note:** All features work without these dependencies, with graceful fallbacks to plain text output.

## Quick Start

### 1. Start the Server

```bash
faracore serve
```

Server starts on `http://127.0.0.1:8000` by default.

### 2. Access the Web UI

Open `http://127.0.0.1:8000` in your browser.

The UI provides:
- Real-time action monitoring
- Event timeline for each action
- One-click approve/deny
- Risk level visualization
- Demo mode with sample data

### 3. Submit Your First Action

**Python SDK:**
```python
from faracore.sdk.client import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")

action = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "echo 'Hello FaraCore'"},
    context={"agent_id": "my-agent"}
)

print(f"Status: {action['status']}")
print(f"Risk Level: {action.get('risk_level')}")
```

**cURL:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "tool": "shell",
    "operation": "run",
    "params": {"cmd": "echo test"}
  }'
```

### 4. View Actions

**CLI:**
```bash
# List all actions (color-coded)
faracore list

# List with full UUIDs
faracore list --full

# Explain why action was allowed/denied
faracore explain <action-id>

# Get specific action
faracore get <action-id>

# View event timeline
faracore events <action-id>

# Stream live actions
faracore tail
```

**Web UI:**
- Click any action row to see details
- View event timeline in the detail drawer
- See risk levels and approval status
- Copy curl commands with one click
- Demo mode indicator (if active)

## Core Concepts

### Actions

An **action** represents a tool call that an AI agent wants to execute. Each action has:

- **ID**: Unique identifier (UUID)
- **Agent ID**: Identifier for the agent making the request
- **Tool**: Tool name (e.g., "shell", "http", "stripe")
- **Operation**: Operation name (e.g., "run", "get", "refund")
- **Params**: Tool-specific parameters
- **Context**: Additional metadata
- **Status**: Current state (pending_approval, approved, executing, etc.)
- **Decision**: Policy decision (allow, deny, require_approval)
- **Risk Level**: Computed risk (low, medium, high)
- **Events**: Timeline of all state changes

### Policy Evaluation

Policies are evaluated in order, and the **first matching rule wins**. If no rules match, the action is **denied by default** (deny-by-default security model).

### Risk Scoring

Risk scoring runs independently of policy rules. Risk rules can trigger automatic approval requirements even if a policy rule would allow the action.

## Policy Configuration

Policies are defined in YAML files. By default, FaraCore looks for `policies/default.yaml`.

### Basic Policy Structure

```yaml
rules:
  # Rules evaluated in order - first match wins
  - match:
      tool: "http"
      op: "get"
    allow: true
    description: "Allow HTTP GET requests"
    risk: "low"

  - match:
      tool: "shell"
      op: "*"
    require_approval: true
    description: "Shell commands require approval"
    risk: "medium"

  # Default deny (must be last)
  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Default deny rule"
    risk: "high"
```

### Match Conditions

Available match conditions:

- `tool`: Tool name (supports `"*"` wildcard)
- `op` / `operation`: Operation name
- `contains`: Substring match in params JSON
- `pattern`: Regex pattern match
- `amount_gt`, `amount_lt`, `amount_gte`, `amount_lte`: Numeric comparisons
- `path_contains`, `path_starts_with`, `path_ends_with`: Path matching
- `method`: HTTP method
- `branch`: Git branch name
- `agent_id`: Agent identifier
- `field` + `value`: Custom field matching

### Policy Effects

Each rule can have one effect:

- `allow: true` - Allow immediately
- `deny: true` - Deny immediately
- `require_approval: true` - Require human approval

### Example Policies

**Block Destructive Shell Commands:**
```yaml
rules:
  - match:
      tool: "shell"
      op: "*"
      pattern: "rm -rf|shutdown|reboot|mkfs"
    deny: true
    description: "Block destructive commands"
    risk: "high"

  - match:
      tool: "*"
      op: "*"
    deny: true
```

**Require Approval for Large Payments:**
```yaml
rules:
  - match:
      tool: "stripe"
      op: "refund"
      amount_gt: 1000
    require_approval: true
    description: "Large refunds require approval"
    risk: "medium"

  - match:
      tool: "stripe"
      op: "*"
    allow: true
    risk: "low"

  - match:
      tool: "*"
      op: "*"
    deny: true
```

## Risk Scoring

Risk scoring provides an additional layer of safety by automatically assessing action risk levels.

### Risk Rules

Define risk rules in your policy file:

```yaml
risk:
  rules:
    - name: dangerous_shell
      when:
        tool: shell
        operation: run
        pattern: "rm -rf"
      risk_level: high
    
    - name: large_payments
      when:
        tool: stripe
        operation: refund
        amount_gt: 1000
      risk_level: medium
```

### Risk Levels

- **low**: Safe operations (default)
- **medium**: Moderate risk
- **high**: High risk - automatically requires approval even if policy allows

### Risk Rule Matching

Risk rules use the same match conditions as policy rules. The first matching risk rule determines the risk level.

### High-Risk Auto-Approval

If an action has `risk_level: high` and a policy rule would `allow` it, FaraCore automatically changes the decision to `require_approval` for safety.

## CLI Usage

FaraCore provides a powerful CLI for managing actions and policies.

### Basic Commands

```bash
# Start server
faracore serve

# Start with policy hot-reload (local mode only)
faracore serve --hot-reload
# Or use environment variable:
# FARACORE_HOT_RELOAD=1 faracore serve
# Note: If policy reload fails, previous valid policy stays active

# List actions (truncated IDs, color-coded)
faracore list

# List with full UUIDs
faracore list --full

# JSON output (for scripting)
faracore list --json

# Get specific action (supports prefix matching)
faracore get 2755d4a8
faracore get 2755d4a8-1000-47e6-873c-b9fd535234ad

# Explain why action was allowed/denied
faracore explain 2755d4a8

# View event timeline
faracore events 2755d4a8

# Approve action
faracore approve 2755d4a8
# or
faracore allow 2755d4a8

# Deny action
faracore deny 2755d4a8

# Replay an action
faracore replay 2755d4a8

# Get ready-to-copy curl commands
faracore curl 2755d4a8

# Stream live actions (SSE, like kubectl logs)
faracore tail

# Show status transitions
faracore logs 2755d4a8
```

### DX Commands

```bash
# Scaffold starter layout
faracore init

# Build web UI
faracore build-ui

# Sanity check environment
faracore doctor

# Compare policy files
faracore policy-diff old.yaml new.yaml

# Generate Docker files
faracore init-docker
```

### Prefix Matching

All commands that take an action ID support **prefix matching**. Use the first 8+ characters:

```bash
# These are equivalent:
faracore get 2755d4a8
faracore get 2755d4a8-1000-47e6-873c-b9fd535234ad
```

If multiple actions match, FaraCore will warn you and list all matches.

### Global Options

```bash
# Specify API host/port
faracore --host 0.0.0.0 --port 9000 list

# Override auth token
faracore --token my-token list

# JSON output
faracore --json get <id>
```

### Command Examples

**List actions with risk levels (color-coded):**
```bash
$ faracore list
┌────────────┬──────────────────┬────────┬────────────┬──────────────┬──────────────────────────────────────┬─────────────────────┐
│ ID         │ Status           │ Risk   │ Tool       │ Operation    │ Params                               │ Created             │
├────────────┼──────────────────┼────────┼────────────┼──────────────┼──────────────────────────────────────┼─────────────────────┤
│ 2755d4a8   │ pending_approval │ high   │ shell     │ run         │ {"cmd": "rm -rf /tmp"}               │ 2026-01-12 10:00:00 │
│ a1b2c3d4   │ allowed          │ low    │ http      │ get         │ {"url": "https://..."}                │ 2026-01-12 09:59:00 │
└────────────┴──────────────────┴────────┴────────────┴──────────────┴──────────────────────────────────────┴─────────────────────┘
```

**Explain why action was allowed/denied:**
```bash
$ faracore explain 2755d4a8
Action Explanation: 2755d4a8

Status: pending_approval
Decision: require_approval
Reason: Shell commands require approval
Risk Level: high

Policy File: /path/to/policies/default.yaml
Policy Version: yaml

Tool: shell
Operation: run
Params: {"cmd": "rm -rf /tmp"}
```

**View event timeline:**
```bash
$ faracore events 2755d4a8
Event Timeline - 2755d4a8
┌─────────────────────┬──────────────────────┬─────────────────────────────┐
│ Time                │ Event                │ Details                     │
├─────────────────────┼──────────────────────┼─────────────────────────────┤
│ 2026-01-12 10:00:00 │ created              │ {"decision": "require_..."} │
│ 2026-01-12 10:00:01 │ decision_made        │ {"decision": "require_..."} │
│ 2026-01-12 10:05:23 │ approved             │ {"reason": "Looks safe"}   │
│ 2026-01-12 10:05:24 │ started              │ {}                          │
│ 2026-01-12 10:05:25 │ succeeded            │ {"reason": "ok"}            │
└─────────────────────┴──────────────────────┴─────────────────────────────┘
```

**Stream live actions (SSE):**
```bash
$ faracore tail
Streaming actions (press CTRL+C to stop)...

[10:00:15] pending_approval  2755d4a8 | shell      | run
[10:00:20] approved          a1b2c3d4 | http       | get
[10:00:25] succeeded         2755d4a8 | shell      | run
```

**Get curl commands:**
```bash
$ faracore curl 2755d4a8
# Action: 2755d4a8-1000-47e6-873c-b9fd535234ad
# Status: pending_approval

# Approve:
curl -X POST http://127.0.0.1:8000/v1/actions/2755d4a8-.../approval \
  -H "Content-Type: application/json" \
  -d '{"token": "abc123...", "approve": true}'

# Deny:
curl -X POST http://127.0.0.1:8000/v1/actions/2755d4a8-.../approval \
  -H "Content-Type: application/json" \
  -d '{"token": "abc123...", "approve": false}'
```

**DX Commands:**
```bash
# Initialize project
$ faracore init
✓ Created starter files:
  • policies/
  • policies/default.yaml
  • .env.example

Next steps:
  1. Review policies/default.yaml
  2. Copy .env.example to .env and customize
  3. Run: faracore serve

# Check environment
$ faracore doctor
✓ Python 3.11.0
✓ Database exists and is writable
✓ Policy file exists: policies/default.yaml
✓ Auth token configured
✓ UI assets found

# Compare policies
$ faracore policy-diff old.yaml new.yaml
Policy Differences:

Old: old.yaml
New: new.yaml

Old rules: 3
New rules: 4

Added rules:
  + Allow HTTP GET requests
```

## Web UI

The FaraCore web UI provides a modern, real-time dashboard for monitoring and managing actions.

### Features

- **Action Table**: View all actions with status, risk level, tool, and operation
- **Event Timeline**: Click any action to see complete event history
- **Real-Time Updates**: Live updates via Server-Sent Events (SSE)
- **Approve/Deny**: One-click approval for pending actions
- **Copy Curl Commands**: Copy ready-to-use curl commands for API calls
- **Demo Badge**: Visual indicator for demo-seeded actions
- **Dark/Light Mode**: Toggle between themes
- **Search & Filters**: Filter by status, agent, tool
- **Pagination**: Navigate large action lists

### Accessing the UI

1. Start the server: `faracore serve`
2. Open `http://127.0.0.1:8000` in your browser

### UI Workflow

1. **View Actions**: See all actions in the main table
2. **Click Action**: Opens detail drawer with full information
3. **View Events**: Scroll to event timeline section
4. **Approve/Deny**: Click buttons if action is pending approval
5. **Copy Curl**: Use copy buttons to get API commands

### Event Timeline

The event timeline shows every state change:

- `created` - Action was created
- `decision_made` - Policy evaluation completed
- `approved` - Human approved the action
- `denied` - Human denied the action
- `started` - Execution began
- `succeeded` - Execution completed successfully
- `failed` - Execution failed

Each event includes:
- Timestamp
- Event type
- Metadata (reason, error, etc.)

## SDK Integration

### Python SDK

```python
from faracore.sdk.client import ExecutionGovernorClient

# Initialize client
client = ExecutionGovernorClient("http://127.0.0.1:8000")

# Submit action
action = client.submit_action(
    tool="shell",
    operation="run",
    params={"cmd": "echo 'Hello World'"},
    context={"agent_id": "my-agent"}
)

# Check status
print(f"Status: {action['status']}")
print(f"Risk Level: {action.get('risk_level')}")
print(f"Decision: {action.get('decision')}")

# If pending approval, wait and check
if action['status'] == 'pending_approval':
    import time
    while True:
        time.sleep(2)
        updated = client.get_action(action['id'])
        if updated['status'] in ('approved', 'denied'):
            break
    print(f"Final status: {updated['status']}")

# Report result
client.report_result(
    action['id'],
    success=True,
    error=None
)
```

### Node.js SDK

```javascript
const { ExecutionGovernorClient } = require('@faracore/sdk');

const client = new ExecutionGovernorClient('http://127.0.0.1:8000');

// Submit action
const action = await client.submitAction({
  tool: 'shell',
  operation: 'run',
  params: { cmd: "echo 'Hello World'" },
  context: { agent_id: 'my-agent' }
});

console.log(`Status: ${action.status}`);
console.log(`Risk Level: ${action.risk_level}`);

// Get events
const events = await client.getEvents(action.id);
console.log(`Event count: ${events.length}`);
```

## LangChain Integration

FaraCore provides a drop-in wrapper for LangChain tools that automatically enforces governance.

### Basic Usage

```python
from langchain.tools import ShellTool
from faracore.sdk.client import ExecutionGovernorClient
from faracore.integrations.langchain.governed_tool import GovernedTool

# Create FaraCore client
client = ExecutionGovernorClient("http://127.0.0.1:8000")

# Wrap LangChain tool
shell_tool = ShellTool()
governed = GovernedTool(
    tool=shell_tool,
    client=client,
    agent_id="my-langchain-agent"
)

# Use in agent - tool calls are automatically governed
result = governed.run("ls -la")
```

### Integration with Agents

```python
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI

# Wrap all tools
governed_tools = [
    GovernedTool(tool=t, client=client, agent_id="agent-1")
    for t in [shell_tool, http_tool]
]

# Create agent with governed tools
agent = initialize_agent(
    tools=governed_tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# Agent tool calls are now governed by FaraCore
response = agent.run("List files in /tmp and fetch a URL")
```

### How It Works

1. **Intercept**: GovernedTool intercepts tool calls before execution
2. **Submit**: Submits to FaraCore for policy evaluation
3. **Wait**: If pending approval, polls until approved/denied
4. **Execute**: Only executes if allowed/approved
5. **Report**: Reports result back to FaraCore

See `examples/langchain/` for complete examples.

## Docker Deployment

### Quick Start

```bash
# Start with demo data
docker compose up

# Access UI
open http://localhost:8000
```

### Custom Build

```bash
# Build image
docker build -t faracore .

# Run with custom config
docker run -p 8000:8000 \
  -e FARACORE_DEMO=1 \
  -e FARACORE_ENABLE_CORS=1 \
  -e FARACORE_HOST=0.0.0.0 \
  -e FARACORE_PORT=8000 \
  -v $(pwd)/policies:/app/policies \
  -v $(pwd)/data:/app/data \
  faracore
```

### Docker Compose

The `docker-compose.yaml` includes:

- **faracore**: Main server
- **demo-agent**: Example agent that submits actions

Edit `docker-compose.yaml` to customize:

```yaml
services:
  faracore:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FARACORE_DEMO=1
      - FARACORE_ENABLE_CORS=1
    volumes:
      - ./data:/app/data
      - ./policies:/app/policies
```

## API Reference

### Endpoints

#### Submit Action
```http
POST /v1/actions
Content-Type: application/json

{
  "agent_id": "string",
  "tool": "string",
  "operation": "string",
  "params": {},
  "context": {}
}
```

#### Get Action
```http
GET /v1/actions/{action_id}
```

#### List Actions
```http
GET /v1/actions?limit=20&offset=0&status=pending_approval&tool=shell
```

#### Get Action Events
```http
GET /v1/actions/{action_id}/events
```

Returns array of events:
```json
[
  {
    "id": "uuid",
    "action_id": "uuid",
    "event_type": "created",
    "meta": {},
    "created_at": "2026-01-12T10:00:00Z"
  }
]
```

#### Approve/Deny Action
```http
POST /v1/actions/{action_id}/approval
Content-Type: application/json

{
  "token": "approval_token",
  "approve": true,
  "reason": "Optional reason"
}
```

#### Start Execution
```http
POST /v1/actions/{action_id}/start
```

#### Report Result
```http
POST /v1/actions/{action_id}/result
Content-Type: application/json

{
  "success": true,
  "error": "Optional error message"
}
```

#### Server-Sent Events
```http
GET /v1/events
```

Returns SSE stream of action updates.

#### Health Check
```http
GET /health
GET /ready
```

#### Metrics
```http
GET /metrics
```

Returns Prometheus metrics.

## Environment Variables

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FARACORE_HOST` | `127.0.0.1` | Server bind address |
| `FARACORE_PORT` | `8000` | Server port |
| `FARACORE_TOKEN` | - | Auth token (overrides `FARA_AUTH_TOKEN`) |
| `FARACORE_ENABLE_CORS` | `1` | Enable CORS (`1`=enabled, `0`=disabled) |
| `FARACORE_DEMO` | - | Demo mode (`1`=seed demo data if DB empty) |

### Policy & Database

| Variable | Default | Description |
|----------|---------|-------------|
| `FARA_POLICY_FILE` | `policies/default.yaml` | Policy file path |
| `FARA_DB_BACKEND` | `sqlite` | Database backend (`sqlite` or `postgres`) |
| `FARA_SQLITE_PATH` | `data/actions.db` | SQLite database path |
| `FARA_POSTGRES_DSN` | - | PostgreSQL connection string |

### Legacy Variables

These are still supported but `FARACORE_*` variants take precedence:

- `FARA_API_HOST` → `FARACORE_HOST`
- `FARA_API_PORT` → `FARACORE_PORT`
- `FARA_AUTH_TOKEN` → `FARACORE_TOKEN`

### Quick Reference

**All configurable via environment variables:**
```bash
# Server
export FARACORE_HOST=0.0.0.0
export FARACORE_PORT=9000
export FARACORE_TOKEN=my-secret-token
export FARACORE_ENABLE_CORS=1

# Policy
export FARA_POLICY_FILE=policies/custom.yaml

# Database
export FARA_DB_BACKEND=sqlite
export FARA_SQLITE_PATH=data/actions.db

# Demo Mode
export FARACORE_DEMO=1
```

**Or use `.env` file:**
```bash
# Copy example
cp .env.example .env

# Edit .env with your settings
# FaraCore automatically reads .env if python-dotenv is installed
```

## Examples

### Example 1: Basic Agent Integration

```python
from faracore.sdk.client import ExecutionGovernorClient

client = ExecutionGovernorClient("http://127.0.0.1:8000")

def execute_command(cmd):
    action = client.submit_action(
        tool="shell",
        operation="run",
        params={"cmd": cmd},
        context={"agent_id": "my-bot"}
    )
    
    if action['status'] == 'denied':
        raise PermissionError(f"Action denied: {action['reason']}")
    
    if action['status'] == 'pending_approval':
        # Wait for approval
        import time
        while True:
            time.sleep(2)
            updated = client.get_action(action['id'])
            if updated['status'] in ('approved', 'denied'):
                break
        
        if updated['status'] == 'denied':
            raise PermissionError("Action denied")
    
    # Execute command
    import subprocess
    result = subprocess.run(cmd, shell=True, capture_output=True)
    
    # Report result
    client.report_result(
        action['id'],
        success=result.returncode == 0,
        error=result.stderr.decode() if result.returncode != 0 else None
    )
    
    return result.stdout.decode()
```

### Example 2: Policy with Risk Scoring

```yaml
rules:
  - match:
      tool: "http"
      op: "*"
    allow: true
    risk: "low"

  - match:
      tool: "shell"
      op: "*"
    require_approval: true
    risk: "medium"

  - match:
      tool: "*"
      op: "*"
    deny: true

risk:
  rules:
    - name: dangerous_commands
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

### Example 3: Docker Compose with Custom Policy

```yaml
version: '3.8'

services:
  faracore:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FARACORE_DEMO=1
      - FARACORE_ENABLE_CORS=1
      - FARA_POLICY_FILE=/app/policies/custom.yaml
    volumes:
      - ./policies:/app/policies
      - ./data:/app/data
```

## Architecture

### Components

- **Policy Engine**: YAML-based policy evaluation with risk scoring
- **Storage Layer**: SQLite (default) or PostgreSQL for actions and events
- **API Server**: FastAPI-based REST API with SSE support
- **Web UI**: React/TypeScript dashboard with real-time updates
- **CLI**: Command-line interface with rich formatting
- **SDKs**: Python and Node.js client libraries

### Data Flow

1. **Agent** submits action via SDK
2. **Policy Engine** evaluates action against rules
3. **Risk Engine** computes risk level
4. **Storage** saves action and creates events
5. **API** returns decision (allow/deny/require_approval)
6. **UI/CLI** displays action for human review
7. **Human** approves/denies via UI or CLI
8. **Executor** runs action if approved
9. **Storage** records execution events
10. **Agent** receives result

### Event Timeline

Every action has a complete event timeline:

```
created → decision_made → [approved|denied] → started → [succeeded|failed]
```

Events are stored in `action_events` table and accessible via:
- API: `GET /v1/actions/{id}/events`
- CLI: `faracore events <id>`
- UI: Action detail drawer

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourorg/faracore.git
cd faracore

# Install in development mode
pip install -e ".[dev,cli]"

# Initialize project
faracore init

# Run tests
pytest

# Start development server with hot-reload
faracore serve --watch

# Build UI (if making UI changes)
cd web && npm install && npm run build
```

### DX Features

FaraCore includes comprehensive developer experience features:

- **`faracore init`** - Scaffold starter layout
- **`faracore explain <id>`** - Explain policy decisions
- **`faracore doctor`** - Environment sanity checks
- **`faracore build-ui`** - Build web UI
- **`faracore serve --hot-reload`** - Hot reload policy files (local mode only)
- **`FARACORE_HOT_RELOAD=1`** - Enable hot reload via environment variable
  - Note: If policy reload fails, previous valid policy stays active
- **`faracore replay <id>`** - Replay actions
- **`faracore tail`** - Stream live actions (SSE)
- **`faracore policy-diff`** - Compare policy files
- **`faracore init-docker`** - Generate Docker config

See [DX_FEATURES.md](DX_FEATURES.md) for complete documentation.

### Project Structure

```
faracore/
├── src/faracore/
│   ├── server/          # FastAPI server
│   ├── sdk/            # Python SDK
│   ├── cli.py          # CLI interface
│   └── integrations/   # LangChain, etc.
├── web/                # React UI
├── policies/           # Policy examples
├── examples/           # Integration examples
└── tests/              # Test suite
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Troubleshooting

### Installation Issues

If installation fails, upgrade pip: `python3 -m pip install --upgrade pip`

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourorg/faracore/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourorg/faracore/discussions)

---

**Built with ❤️ for safe AI agent operations**
