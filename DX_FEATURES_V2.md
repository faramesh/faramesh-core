# FaraCore DX Upgrade - Feature Summary

This document summarizes the major DX (Developer Experience) improvements added to FaraCore.

## ✅ Completed Features

### CLI Rewrite & Namespace

**New `fara action` namespace:**
- `fara action submit <agent> <tool> <operation> --param key=value` - Submit actions without JSON
- `fara action approve <id>` - Approve pending actions
- `fara action deny <id>` - Deny pending actions  
- `fara action start <id>` - Start execution
- `fara action replay <id>` - Replay an action
- `fara history` - Show action history (alias for `list`)

**Features:**
- ✅ Rich colorized output with tables
- ✅ Truncated UUIDs (use `--full` for complete IDs)
- ✅ Next-action suggestions after submit
- ✅ `--param key=value` parsing (no JSON needed)
- ✅ Prefix matching for action IDs

### REPL Mode

**Interactive Shell:**
- `fara shell` - Start interactive REPL
- Commands: `submit`, `approve`, `deny`, `start`, `replay`, `history`, `get`, `explain`
- Tab completion for command names
- Always shows helpful next-action suggestions
- Example: `submit agent=bot tool=shell op=run cmd="echo hi"`

### Web Playground Panel

**Backend `/play` route:**
- Form inputs: agent_id, tool, op, params editor
- Live JSON response
- Auto-shows:
  - `curl` equivalent
  - JS SDK equivalent  
  - Python SDK equivalent

**Next.js Integration:**
- `/app/play` route embeds playground via iframe
- Configurable via `NEXT_PUBLIC_FARACORE_PLAY_URL`

### GUI Action Composer

**Vite UI Modal:**
- "New Action" button in main UI
- Dropdowns for tool & operation
- Param builder (JSON editor)
- Submit action
- Inline approve/start if pending
- Shows SDK snippets after submission

### SDK Snippet Generator

**Every action response includes:**
- `js_example` - JavaScript SDK code snippet
- `python_example` - Python SDK code snippet
- Auto-generated from action details
- Shown in CLI output, `/play` route, and UI

### Request-by-File Support

**YAML/JSON file support:**
- `fara apply ./action.yaml` - Submit from file
- Schema maps to request body
- Supports both YAML and JSON formats

### Token Creation & DX

**Token management:**
- `fara token create <name> --ttl 1h` - Create token
- `fara token list` - List all tokens
- `fara token revoke <id>` - Revoke token
- Prints export line: `export FARACORE_TOKEN=...`
- File-based storage in `~/.faracore_tokens.json`

### Policy Editing DX

**Policy commands:**
- `fara policy new <name>` → Scaffold file into `policies/user/` (via `init`)
- `fara policy validate <file>` - Lint YAML + explain failures
- `fara policy diff old.yaml new.yaml` - Show differences
- `fara policy test <yaml> --dry-run <action spec>` - Test policy

### Tail Stream + Event Feed

**SSE endpoint:**
- `GET /v1/events` - Server-Sent Events stream
- Used by UI tail + CLI tail
- Real-time action updates
- CLI `fara tail` command streams live actions

### Doctor Command

**Environment check:**
- `fara doctor` prints:
  - DB writable?
  - Policy loaded?
  - Token configured?
  - UI built?
- Suggests fixes for issues

### Build Helper

**UI build automation:**
- `fara build-ui` → runs `npm install` + `npm build` + copies assets
- Copies `web/dist` → `src/faracore/web`
- Warns if UI hasn't been built

### CORS + ENV Config

**Environment variables:**
- `FARACORE_HOST` - API host (default: 127.0.0.1)
- `FARACORE_PORT` - API port (default: 8000)
- `FARA_POLICY_FILE` - Policy file path
- `FARACORE_ENABLE_CORS` - CORS control (default: enabled)
- `FARACORE_TOKEN` - Auth token
- All documented in `.env.example` (via `fara init`)

## 🧪 Testing

**New tests added:**
- `test_action_response_includes_sdk_examples` - Verifies snippet generation
- `test_cli_action_namespace` - Tests action submit/approve/deny/start
- `test_cli_apply_yaml` - Tests file-based submission
- `test_token_commands` - Tests token create/list/revoke
- `test_policy_commands` - Tests policy validate/test

## 📝 Usage Examples

### CLI Examples

```bash
# Submit action (no JSON needed)
fara action submit my-agent shell run --param cmd="echo hello"

# Approve pending action
fara action approve 2755d4a8

# Start execution
fara action start 2755d4a8

# Interactive REPL
fara shell
> submit agent=bot tool=http op=get url="https://api.example.com"
> approve 123
> start 123

# Submit from file
fara apply ./action.yaml

# Stream live actions
fara tail

# Explain policy decision
fara explain 2755d4a8

# Create token
fara token create my-token --ttl 24h
export FARACORE_TOKEN=...

# Check environment
fara doctor
```

### API Examples

Every action response now includes SDK snippets:

```json
{
  "id": "...",
  "status": "pending_approval",
  "js_example": "import { ExecutionGovernorClient } from \"@fara/core\";\n...",
  "python_example": "from faracore.sdk.client import ExecutionGovernorClient\n..."
}
```

### Web UI

1. Click "New Action" button
2. Fill in form (tool/op dropdowns, params JSON)
3. Submit → See snippets + inline approve/start buttons
4. Or visit `/play` for standalone playground

## 🎯 Architecture Notes

- **No breaking changes** - All existing REST contracts preserved
- **Backward compatible** - Raw curl + API still work exactly as before
- **Layered approach** - New UX layers on top of existing API
- **SSE reuse** - Single `/v1/events` endpoint used by CLI tail + UI tail
- **Snippet generation** - Server-side, included in all action responses
- **Hybrid UI** - Next.js site embeds Vite playground via iframe

## 🚀 Next Steps

Potential future enhancements:
- Enhanced REPL with more tab completion (field names, tool/op suggestions)
- Policy visual editor in UI
- Action replay with modifications
- Bulk approve/deny operations
- Action templates/presets
- More comprehensive e2e tests
