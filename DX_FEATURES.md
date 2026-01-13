# FaraCore DX/UX Features

Complete guide to all developer experience and user experience features in FaraCore.

## Must-Have DX Commands

### `faracore init`

Scaffolds a working starter layout for new projects.

**What it creates:**
- `policies/` directory
- `policies/default.yaml` with deny-by-default rule
- `.env.example` with all configurable environment variables

**Usage:**
```bash
faracore init
faracore init --force  # Overwrite existing files
```

**Output:**
```
✓ Created starter files:
  • policies/
  • policies/default.yaml
  • .env.example

Next steps:
  1. Review policies/default.yaml
  2. Copy .env.example to .env and customize
  3. Run: faracore serve
```

### `faracore explain <ACTION_ID>`

Explains why an action was allowed, denied, or required approval.

**Usage:**
```bash
faracore explain 2755d4a8
faracore explain 2755d4a8-1000-47e6-873c-b9fd535234ad
```

**Output:**
```
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

**Features:**
- Shows policy file path
- Shows risk level and reason
- Supports prefix matching (8+ chars)
- Color-coded output (if rich installed)

### CLI Pretty-Print Upgrade

All CLI outputs now feature:
- **Colors**: Red (deny/failed), Yellow (pending), Green (allow/success), Blue (info)
- **Aligned columns**: Professional table formatting
- **Risk levels**: Displayed in list and get commands

**Examples:**
```bash
# Color-coded list
faracore list

# Full UUIDs
faracore list --full

# JSON output (for scripting)
faracore list --json
```

**Output format:**
- With `rich`: Beautiful tables with colors
- With `tabulate`: Grid tables
- Fallback: Plain aligned text

### `faracore build-ui`

Builds the web UI automatically.

**Usage:**
```bash
faracore build-ui
```

**Behavior:**
- Detects `web/` directory automatically
- Runs `npm install` if `node_modules` missing
- Runs `npm run build`
- Copies/minifies static files to app's static folder
- Prints success or actionable errors

**Output:**
```
Building UI...
Installing dependencies...
Running npm run build...
✓ UI built successfully
```

## High ROI DX Commands

### `faracore doctor`

Sanity checks your environment.

**Checks:**
- ✅ Python version (requires 3.9+)
- ✅ Database exists and is writable
- ✅ Policy file exists
- ✅ Auth token configured (optional)
- ✅ UI assets exist (optional)

**Usage:**
```bash
faracore doctor
```

**Output:**
```
✓ Python 3.11.0
✓ Database exists and is writable
✓ Policy file exists: policies/default.yaml
✓ Auth token configured
✓ UI assets found

✓ All checks passed!
```

**Exit codes:**
- `0`: All checks passed (or only warnings)
- `1`: Issues found

### `faracore serve --watch`

Hot reload mode for policy files.

**Usage:**
```bash
faracore serve --watch
```

**Behavior:**
- Watches policy file for changes
- Automatically reloads policy when modified
- Logs "Policy reloaded" on success
- Warns if reload fails (keeps running)
- No server restart required

**Requirements:**
- `watchdog` package (optional, falls back gracefully)

**Output:**
```
Watching policy file: /path/to/policies/default.yaml
Starting FaraCore server on http://127.0.0.1:8000
Policy hot-reload enabled (--watch)
Press CTRL+C to stop

✓ Policy reloaded  # When file changes
```

### `faracore replay <ACTION_ID>`

Replays an action execution.

**Usage:**
```bash
faracore replay 2755d4a8
```

**Behavior:**
- Only works if original status was `allowed` or `approved`
- Creates new action with same payload
- Marks `replayed_from=<old_id>` in context
- Never auto-approves (goes through policy again)
- Returns new action ID

**Output:**
```
✓ Replayed action
Original: 2755d4a8-1000-47e6-873c-b9fd535234ad
New: a1b2c3d4-2000-57f7-984d-c0fe646345be
Status: pending_approval
```

### `faracore tail` (Upgraded)

Streams live actions via SSE (like `kubectl logs`).

**Usage:**
```bash
faracore tail
```

**Behavior:**
- Connects to `/v1/events` SSE endpoint
- One line per event
- Color-coded by status
- Real-time streaming (no polling delay)

**Output:**
```
Streaming actions (press CTRL+C to stop)...

[10:00:15] pending_approval  2755d4a8 | shell      | run
[10:00:20] approved          a1b2c3d4 | http       | get
[10:00:25] succeeded         2755d4a8 | shell      | run
```

**Fallback:**
- If `sseclient` not installed, falls back to polling (2s interval)
- Still color-coded

**Requirements:**
- `sseclient` package (optional, falls back gracefully)

## Bonus Features

### `faracore policy-diff <old.yaml> <new.yaml>`

Shows differences between two policy files.

**Usage:**
```bash
faracore policy-diff old.yaml new.yaml
```

**Output:**
```
Policy Differences:

Old: old.yaml
New: new.yaml

Old rules: 3
New rules: 4

Added rules:
  + Allow HTTP GET requests

Removed rules:
  - Block all shell commands
```

**Features:**
- Shows added/removed rules
- Shows rule count changes
- Prints "No changes detected" if identical
- Readable side-by-side comparison

### `faracore init-docker`

Generates Docker configuration files.

**Usage:**
```bash
faracore init-docker
faracore init-docker --force  # Overwrite existing files
```

**Creates:**
- `docker-compose.yaml` with faracore service
- `Dockerfile` for building images
- `.env.example` (if not exists)

**Default setup:**
- App on `0.0.0.0:8000`
- Binds `data/` directory
- Optional demo-agent service (commented)
- All env vars configured

**Output:**
```
✓ Created Docker files:
  • docker-compose.yaml
  • Dockerfile
  • .env.example

Next steps:
  1. Review docker-compose.yaml
  2. Run: docker compose up
```

## Color Coding

All CLI outputs use consistent color coding:

- **Red**: Denied, failed, high risk, errors
- **Yellow**: Pending approval, medium risk, warnings
- **Green**: Allowed, approved, succeeded, low risk, success
- **Blue**: Info, executing, created timestamps
- **Cyan**: IDs, headers, metadata

## Prefix Matching

All commands that take action IDs support prefix matching:

```bash
# These are equivalent:
faracore get 2755d4a8
faracore get 2755d4a8-1000-47e6-873c-b9fd535234ad

# If multiple matches:
faracore get 27
# Error: Multiple actions match prefix '27':
#   2755d4a8-... - pending_approval
#   27a1b2c3-... - allowed
# Please use a longer prefix to uniquely identify the action.
```

## UI Polish

### Features Added

1. **Logo**: FaraMesh logo in top-left (from `/app/logo.png`)
2. **Truncated UUIDs**: 8 chars by default, full ID on hover/click
3. **Color-coded Statuses**: 
   - Yellow: pending_approval
   - Blue: approved
   - Green: allowed/succeeded
   - Red: denied/failed
   - Purple: executing (with pulse)
4. **Better Empty States**: Helpful message with code example
5. **Demo Mode Hint**: Banner when demo mode is active

### Empty State

When no actions exist, UI shows:
- Large icon (📋)
- "No actions yet" message
- Quick start code example
- Instructions to submit via SDK

### Demo Mode Indicator

When `FARACORE_DEMO=1` and demo actions exist:
- Yellow banner at top: "Demo mode is active"
- Demo badge on demo actions
- Clear visual distinction

## Environment Variables

All serve-time config from environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `FARACORE_HOST` | `127.0.0.1` | Server bind address |
| `FARACORE_PORT` | `8000` | Server port |
| `FARACORE_TOKEN` | - | Auth token |
| `FARACORE_ENABLE_CORS` | `1` | CORS control (`1`=enabled, `0`=disabled) |
| `FARACORE_DEMO` | - | Demo mode (`1`=seed demo data) |
| `FARA_POLICY_FILE` | `policies/default.yaml` | Policy file path |

**Precedence:** CLI flags > ENV vars > defaults

## Testing

All features are tested:

```bash
# Run DX tests
pytest tests/test_cli_dx.py -v

# Test specific command
pytest tests/test_cli_dx.py::test_init_command -v
```

## Optional Dependencies

For enhanced CLI output:
```bash
pip install -e ".[cli]"
```

This installs:
- `rich` - Beautiful terminal output
- `tabulate` - Table formatting
- `watchdog` - File watching (for --watch)
- `sseclient` - SSE streaming (for tail)

All features work without these, with graceful fallbacks.

## Examples

### Complete Workflow

```bash
# 1. Initialize project
faracore init

# 2. Check environment
faracore doctor

# 3. Start server with hot-reload
faracore serve --watch

# 4. In another terminal, submit action
python submit_action.py

# 5. View actions
faracore list

# 6. Explain why action needs approval
faracore explain <action-id>

# 7. Stream live updates
faracore tail

# 8. Approve action
faracore approve <action-id>

# 9. View events
faracore events <action-id>
```

### Policy Development

```bash
# Edit policy
vim policies/default.yaml

# Server auto-reloads (if --watch)
# Or manually refresh
faracore policy-refresh

# Compare with old version
faracore policy-diff old.yaml policies/default.yaml

# Test policy
faracore policy-test test_action.json
```

### Docker Workflow

```bash
# Generate Docker files
faracore init-docker

# Review and customize
vim docker-compose.yaml

# Build and run
docker compose up

# Access UI
open http://localhost:8000
```

## Summary

All DX/UX features are:
- ✅ Fully implemented
- ✅ Tested
- ✅ Documented
- ✅ Backward compatible
- ✅ Cross-platform (Mac/Linux)
- ✅ Works with SQLite (no Postgres required)

**No breaking changes** - all existing functionality preserved.
