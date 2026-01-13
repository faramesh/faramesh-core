# Bonus Test Scenarios - Expected Behavior

This document describes the expected behavior for the bonus test scenarios.

## Setup

1. **Start server with test policy:**
```bash
export FARA_POLICY_FILE=policies/test_bonus.yaml
export FARACORE_TOKEN=dev-token
faracore serve --hot-reload
```

2. **Or use default policy** (which requires approval for shell, denies unknown tools)

## Test Scenarios

### 1. Missing token → 401 (not 403)

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"ls"}}'
```

**Expected Response:**
- HTTP Status: **401 Unauthorized**
- Body: `{"detail":"Missing or invalid Authorization header"}`

**Note:** The `AuthMiddleware` returns **401**, not 403. This is correct HTTP semantics (401 = authentication required, 403 = authenticated but not authorized).

### 2. Unknown tool → deny

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"alien","operation":"warp","params":{}}'
```

**Expected Response:**
- HTTP Status: **200 OK**
- Body includes:
  - `"status": "denied"`
  - `"decision": "deny"`
  - `"reason": "Default deny rule"` (or similar from policy)

**Why:** The default policy has a catch-all deny rule:
```yaml
- match:
    tool: "*"
    op: "*"
  deny: true
```

### 3. Dangerous shell → deny

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"rm -rf /"}}'
```

**Expected Response (with test_bonus.yaml):**
- HTTP Status: **200 OK**
- Body includes:
  - `"status": "denied"`
  - `"decision": "deny"`
  - `"reason": "Deny dangerous shell commands"`

**Why:** The test policy has a rule that matches `pattern: "rm -rf|shutdown|reboot|mkfs|format"` in the params.

**Expected Response (with default.yaml):**
- HTTP Status: **200 OK**
- Body includes:
  - `"status": "pending_approval"` (because default policy requires approval for all shell commands)
  - `"risk_level": "high"` (from risk rules matching dangerous pattern)

**Note:** The default policy doesn't have a deny rule for dangerous patterns, so it falls through to `require_approval: true` for all shell commands. The risk level will be "high" due to the risk rule matching the pattern.

### 4. Approval path → pending_approval

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"deploy","tool":"kubernetes","operation":"deploy","params":{"namespace":"prod"}}'
```

**Expected Response (with test_bonus.yaml):**
- HTTP Status: **200 OK**
- Body includes:
  - `"status": "pending_approval"`
  - `"decision": "require_approval"`
  - `"approval_token": "..."` (present)
  - `"risk_level": "high"` (from risk rule matching "prod" in params)

**Expected Response (with default.yaml):**
- HTTP Status: **200 OK**
- Body includes:
  - `"status": "denied"` (because default policy denies unknown tools)
  - `"decision": "deny"`

**To approve:**
```bash
# Get the action ID from response
ACTION_ID="<id-from-response>"

# Approve via CLI
faracore allow $ACTION_ID

# Or via curl
curl -X POST "http://127.0.0.1:8000/v1/actions/$ACTION_ID/approval" \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"token":"<approval_token>","approve":true}'
```

**After approval:**
- Action status changes to `"approved"`
- Can then call `faracore start <ID>` or POST to `/v1/actions/{id}/start` to execute

## Running the Tests

Use the provided test script:

```bash
# Set environment variables
export BASE_URL=http://127.0.0.1:8000
export TOKEN=dev-token

# Run tests
./test_bonus_scenarios.sh
```

Or test manually with the curl commands above.

## Policy Pattern Matching

The policy engine supports pattern matching via the `pattern` key in match conditions:

```yaml
- match:
    tool: "shell"
    pattern: "rm -rf|shutdown|reboot"
  deny: true
```

The pattern is a regex that searches in the JSON-serialized params. So `"rm -rf"` in `params.cmd` will match.

## Risk Rules

Risk rules compute `risk_level` independently and can trigger `require_approval` if `risk_level == "high"`:

```yaml
risk:
  rules:
    - name: dangerous_shell
      when:
        tool: shell
        operation: run
        pattern: "rm -rf|shutdown|reboot|mkfs"
      risk_level: high
```

Risk level affects the `risk_level` field in the action response but doesn't change the decision (that's done by policy rules).

## Summary

| Scenario | Expected Status | Expected Decision | Notes |
|----------|----------------|-------------------|-------|
| Missing token | N/A | N/A | HTTP 401 (not 403) |
| Unknown tool | `denied` | `deny` | Caught by default deny rule |
| Dangerous shell (test_bonus.yaml) | `denied` | `deny` | Pattern match denies it |
| Dangerous shell (default.yaml) | `pending_approval` | `require_approval` | Falls through to require_approval, risk=high |
| Kubernetes deploy (test_bonus.yaml) | `pending_approval` | `require_approval` | Requires approval, risk=high (prod) |
| Kubernetes deploy (default.yaml) | `denied` | `deny` | Unknown tool, caught by default deny |
