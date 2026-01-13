# Bonus Tests - Verification Guide

## Quick Test Commands

### Prerequisites
```bash
# Start server with auth token
export FARACORE_TOKEN=dev-token
faracore serve --hot-reload
```

### Test 1: Missing Token → 401
```bash
curl -i -X POST http://127.0.0.1:8000/v1/actions \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"ls"}}'
```
**Expected:** HTTP 401 with `{"detail":"Missing or invalid Authorization header"}`

### Test 2: Unknown Tool → Deny
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"alien","operation":"warp","params":{}}' | jq '.status, .decision'
```
**Expected:** `"denied"` and `"deny"`

### Test 3: Dangerous Shell → Deny (with test policy)
```bash
# First, switch to test policy
export FARA_POLICY_FILE=policies/test_bonus.yaml
faracore policy-refresh

# Then test
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"rm -rf /"}}' | jq '.status, .decision, .reason'
```
**Expected:** `"denied"`, `"deny"`, reason mentions dangerous command

### Test 4: Approval Path
```bash
# With test_bonus.yaml policy
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"deploy","tool":"kubernetes","operation":"deploy","params":{"namespace":"prod"}}' | jq '.status, .decision, .approval_token'
```
**Expected:** `"pending_approval"`, `"require_approval"`, approval_token present

**Then approve:**
```bash
# Get ID from response
ACTION_ID="<id>"
faracore allow $ACTION_ID

# Verify status changed
curl -X GET "http://127.0.0.1:8000/v1/actions/$ACTION_ID" \
  -H "Authorization: Bearer dev-token" | jq '.status'
```
**Expected:** `"approved"`

## Current Implementation Notes

### Auth Behavior
- **Missing token** → **401 Unauthorized** (not 403)
- This is correct HTTP semantics: 401 = authentication required, 403 = authenticated but forbidden
- The `AuthMiddleware` returns 401 for missing/invalid tokens

### Policy Evaluation
- **Pattern matching** works via `pattern` key in match conditions
- Pattern is regex searched in JSON-serialized params
- Example: `pattern: "rm -rf"` will match `params.cmd = "rm -rf /tmp"`

### Risk Rules
- Risk rules compute `risk_level` (low/medium/high)
- Risk level is independent of policy decision
- High risk doesn't automatically deny (policy rules control that)

### Default Policy Behavior
- `default.yaml` requires approval for all shell commands
- `default.yaml` denies all unknown tools (catch-all deny rule)
- To deny dangerous shell commands, add a deny rule with pattern matching

## Test Policy (test_bonus.yaml)

The `policies/test_bonus.yaml` file includes:
- Deny rule for dangerous shell patterns
- Require approval for safe shell commands
- Require approval for kubernetes operations
- Default deny for unknown tools

This policy is designed to test all bonus scenarios.
