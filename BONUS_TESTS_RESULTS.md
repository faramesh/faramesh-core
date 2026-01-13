# Bonus Tests - Expected Results

## Policy Engine Tests (Offline)

These tests verify policy evaluation logic without requiring a running server.

### Test 1: Dangerous Shell Command
**Policy:** `test_bonus.yaml`  
**Input:** `tool="shell"`, `operation="run"`, `params={"cmd": "rm -rf /"}`  
**Expected:** `decision=DENY`, `reason="Deny dangerous shell commands"`, `risk_level="high"`

### Test 2: Unknown Tool
**Policy:** `test_bonus.yaml`  
**Input:** `tool="alien"`, `operation="warp"`, `params={}`  
**Expected:** `decision=DENY`, `reason="Default deny rule"`, `risk_level="low"`

### Test 3: Kubernetes Deploy (Requires Approval)
**Policy:** `test_bonus.yaml`  
**Input:** `tool="kubernetes"`, `operation="deploy"`, `params={"namespace": "prod"}`  
**Expected:** `decision=REQUIRE_APPROVAL`, `reason="Kubernetes operations require approval"`, `risk_level="high"`

## API Tests (Requires Running Server)

### Test 1: Missing Token → 401
**Request:**
```bash
curl -i -X POST http://127.0.0.1:8000/v1/actions \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"ls"}}'
```
**Expected Response:**
- HTTP Status: **401 Unauthorized**
- Body: `{"detail":"Missing or invalid Authorization header"}`

**Implementation:** `AuthMiddleware` returns 401 (not 403) for missing/invalid tokens. This is correct HTTP semantics.

### Test 2: Unknown Tool → Deny
**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"alien","operation":"warp","params":{}}'
```
**Expected Response:**
- HTTP Status: **200 OK**
- Body: `{"status": "denied", "decision": "deny", "reason": "Default deny rule", ...}`

### Test 3: Dangerous Shell → Deny
**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"rm -rf /"}}'
```
**Expected Response (with test_bonus.yaml):**
- HTTP Status: **200 OK**
- Body: `{"status": "denied", "decision": "deny", "reason": "Deny dangerous shell commands", "risk_level": "high", ...}`

**Expected Response (with default.yaml):**
- HTTP Status: **200 OK**
- Body: `{"status": "pending_approval", "decision": "require_approval", "risk_level": "high", ...}`

**Note:** Default policy doesn't deny dangerous patterns, so it requires approval instead.

### Test 4: Approval Path → Pending
**Request:**
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"deploy","tool":"kubernetes","operation":"deploy","params":{"namespace":"prod"}}'
```
**Expected Response (with test_bonus.yaml):**
- HTTP Status: **200 OK**
- Body: `{"status": "pending_approval", "decision": "require_approval", "approval_token": "...", "risk_level": "high", ...}`

**Then approve:**
```bash
# Get ACTION_ID and approval_token from response
faracore allow <ACTION_ID>
# or
curl -X POST "http://127.0.0.1:8000/v1/actions/<ACTION_ID>/approval" \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"token":"<approval_token>","approve":true}'
```

**After approval:**
- Action status: `"approved"`
- Can then start execution: `faracore start <ACTION_ID>`

## Summary

All bonus test scenarios are supported by the current FaraCore implementation:

✅ **Missing token** → 401 (correct HTTP semantics)  
✅ **Unknown tool** → Denied (default deny rule)  
✅ **Dangerous shell** → Denied (with pattern matching policy) or Pending (with default policy)  
✅ **Approval path** → Pending approval, then can approve and execute  

The test policy (`policies/test_bonus.yaml`) is configured to demonstrate all these scenarios.
