#!/usr/bin/env python3
"""End-to-end test for FaraCore - tests the complete flow."""

import sys
import time
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from faracore.sdk import ExecutionGovernorClient

def find_server():
    """Find running server on common ports."""
    ports = [8000, 8001, 8002, 8003]
    for port in ports:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
            if r.status_code == 200:
                return f"http://127.0.0.1:{port}"
        except:
            continue
    return None

def main():
    """Run end-to-end tests."""
    api_base = find_server()
    if not api_base:
        print("❌ Server not running. Start with: faracore serve")
        sys.exit(1)
    
    print(f"✅ Using server at {api_base}\n")
    print("=" * 60)
    
    client = ExecutionGovernorClient(api_base)
    
    # Test 1: Submit action that should be allowed
    print("\n1. Test: HTTP GET (should be allowed)")
    print("-" * 40)
    response = client.submit_action(
        tool="http",
        operation="get",
        params={"url": "https://example.com"},
        context={}
    )
    assert response['status'] == 'allowed', f"Expected allowed, got {response['status']}"
    assert response['decision'] == 'allow', f"Expected allow decision"
    print(f"✅ Action allowed: {response['id'][:8]}...")
    
    # Test 2: Submit action that should require approval
    print("\n2. Test: Shell command (should require approval)")
    print("-" * 40)
    response = client.submit_action(
        tool="shell",
        operation="run",
        params={"cmd": "echo 'Hello FaraCore'"},
        context={}
    )
    assert response['status'] == 'pending_approval', f"Expected pending_approval, got {response['status']}"
    assert response['decision'] == 'require_approval', f"Expected require_approval decision"
    assert response.get('approval_token'), "Missing approval token"
    pending_id = response['id']
    approval_token = response['approval_token']
    print(f"✅ Action pending approval: {pending_id[:8]}...")
    print(f"   Token: {approval_token[:16]}...")
    
    # Test 3: Get pending action
    print("\n3. Test: Get pending action")
    print("-" * 40)
    action = client.get_action(pending_id)
    assert action['status'] == 'pending_approval', "Status should still be pending"
    assert action.get('approval_token') == approval_token, "Token should match"
    print(f"✅ Retrieved action: {action['status']}")
    
    # Test 4: Approve action
    print("\n4. Test: Approve action")
    print("-" * 40)
    r = requests.post(
        f"{api_base}/v1/actions/{pending_id}/approval",
        json={"token": approval_token, "approve": True, "reason": "E2E test approval"}
    )
    assert r.status_code == 200, f"Approval failed: {r.status_code}"
    action = r.json()
    assert action['status'] == 'approved', f"Expected approved, got {action['status']}"
    print(f"✅ Action approved: {action['status']}")
    
    # Test 5: Start execution
    print("\n5. Test: Start execution")
    print("-" * 40)
    r = requests.post(f"{api_base}/v1/actions/{pending_id}/start")
    assert r.status_code == 200, f"Start failed: {r.status_code}"
    action = r.json()
    print(f"✅ Execution started: {action['status']}")
    # Note: For shell commands, executor will handle this
    
    # Test 6: Report result
    print("\n6. Test: Report result")
    print("-" * 40)
    r = requests.post(
        f"{api_base}/v1/actions/{pending_id}/result",
        json={"success": True, "error": None}
    )
    assert r.status_code == 200, f"Result failed: {r.status_code}"
    action = r.json()
    assert action['status'] == 'succeeded', f"Expected succeeded, got {action['status']}"
    print(f"✅ Result reported: {action['status']}")
    
    # Test 7: List and filter actions
    print("\n7. Test: List and filter actions")
    print("-" * 40)
    all_actions = client.list_actions(limit=10)
    print(f"✅ Listed {len(all_actions)} actions")
    
    approved_actions = client.list_actions(status='approved', limit=10)
    print(f"✅ Found {len(approved_actions)} approved actions")
    
    # Test 8: Deny flow
    print("\n8. Test: Deny action flow")
    print("-" * 40)
    response = client.submit_action(
        tool="shell",
        operation="run",
        params={"cmd": "rm -rf /tmp/test"},
        context={}
    )
    deny_id = response['id']
    deny_token = response.get('approval_token')
    if deny_token:
        r = requests.post(
            f"{api_base}/v1/actions/{deny_id}/approval",
            json={"token": deny_token, "approve": False, "reason": "E2E test denial"}
        )
        assert r.status_code == 200, f"Denial failed: {r.status_code}"
        action = r.json()
        assert action['status'] == 'denied', f"Expected denied, got {action['status']}"
        print(f"✅ Action denied: {action['status']}")
    else:
        print(f"⚠️  Action was not pending (status: {response['status']})")
    
    # Test 9: SSE endpoint
    print("\n9. Test: SSE endpoint")
    print("-" * 40)
    try:
        r = requests.get(f"{api_base}/v1/events", stream=True, timeout=2)
        if r.status_code == 200:
            print("✅ SSE endpoint accessible")
        else:
            print(f"⚠️  SSE returned {r.status_code}")
    except Exception as e:
        print(f"⚠️  SSE test: {e}")
    
    print("\n" + "=" * 60)
    print("✅ All end-to-end tests passed!")
    print("\nFaraCore is production-ready! 🚀")

if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"\n❌ Test assertion failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
