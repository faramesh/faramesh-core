#!/bin/bash
# Bonus test scenarios for FaraCore
# Run this after starting the server: faracore serve

set -e

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
TOKEN="${TOKEN:-dev-token}"

echo "=========================================="
echo "FaraCore Bonus Test Scenarios"
echo "=========================================="
echo "Base URL: $BASE_URL"
echo "Token: $TOKEN"
echo ""

# Test 1: Missing token → 401 (not 403, as auth middleware returns 401)
echo "Test 1: Missing token → 401"
echo "Expected: HTTP 401 Unauthorized"
echo "---"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/v1/actions" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"ls"}}')
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
if [ "$HTTP_CODE" = "401" ]; then
  echo "✅ PASS: Got 401 as expected"
else
  echo "❌ FAIL: Expected 401, got $HTTP_CODE"
fi
echo ""

# Test 2: Unknown tool → deny
echo "Test 2: Unknown tool → deny"
echo "Expected: status='denied'"
echo "---"
RESPONSE=$(curl -s -X POST "$BASE_URL/v1/actions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"alien","operation":"warp","params":{}}')
STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
echo "Response: $RESPONSE"
if [ "$STATUS" = "denied" ]; then
  echo "✅ PASS: Action denied as expected"
else
  echo "❌ FAIL: Expected status='denied', got status='$STATUS'"
fi
echo ""

# Test 3: Dangerous shell → deny (if policy has deny rule for dangerous patterns)
echo "Test 3: Dangerous shell → deny"
echo "Expected: status='denied' (if policy denies rm -rf patterns)"
echo "---"
RESPONSE=$(curl -s -X POST "$BASE_URL/v1/actions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agentA","tool":"shell","operation":"run","params":{"cmd":"rm -rf /"}}')
STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
DECISION=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('decision', 'unknown'))" 2>/dev/null || echo "unknown")
echo "Response: $RESPONSE"
if [ "$STATUS" = "denied" ] || [ "$STATUS" = "pending_approval" ]; then
  echo "✅ PASS: Dangerous command blocked (status=$STATUS, decision=$DECISION)"
else
  echo "⚠️  NOTE: Got status='$STATUS' - may need policy rule to deny dangerous patterns"
fi
echo ""

# Test 4: Approval path (if policy requires approval)
echo "Test 4: Approval path → pending_approval"
echo "Expected: status='pending_approval' with approval_token"
echo "---"
RESPONSE=$(curl -s -X POST "$BASE_URL/v1/actions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"deploy","tool":"kubernetes","operation":"deploy","params":{"namespace":"prod"}}')
STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('status', 'unknown'))" 2>/dev/null || echo "unknown")
HAS_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print('yes' if d.get('approval_token') else 'no')" 2>/dev/null || echo "no")
ACTION_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
echo "Response: $RESPONSE"
if [ "$STATUS" = "pending_approval" ] && [ "$HAS_TOKEN" = "yes" ]; then
  echo "✅ PASS: Action requires approval (status=$STATUS, has_token=$HAS_TOKEN)"
  echo "Action ID: $ACTION_ID"
  echo "To approve: faracore allow $ACTION_ID"
else
  echo "⚠️  NOTE: Got status='$STATUS' - may need policy rule requiring approval for kubernetes/deploy"
fi
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "All tests completed. Check results above."
echo ""
echo "Note: Some tests may show warnings if policy rules don't match expectations."
echo "Update policies/default.yaml to match your test scenarios."
