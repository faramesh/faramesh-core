#!/usr/bin/env python3
"""Comprehensive end-to-end test for all action statuses."""

import sys
import time
import requests
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

def find_server():
    """Find running server."""
    ports = [8000, 8001, 8002, 8003, 8010]
    for port in ports:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
            if r.status_code == 200:
                return f"http://127.0.0.1:{port}"
        except:
            continue
    return None

def test_all_statuses(api_base):
    """Test all possible action statuses."""
    print("=" * 70)
    print("FaraCore Comprehensive Status Test")
    print("=" * 70)
    
    results = {
        "allowed": False,
        "denied": False,
        "pending_approval": False,
        "approved": False,
        "executing": False,
        "succeeded": False,
        "failed": False,
    }
    
    # Test 1: ALLOWED status (HTTP GET)
    print("\n1. Testing ALLOWED status...")
    print("-" * 70)
    r = requests.post(f"{api_base}/v1/actions", json={
        "agent_id": "status-test",
        "tool": "http",
        "operation": "get",
        "params": {"url": "https://example.com"},
        "context": {}
    })
    action = r.json()
    print(f"   Action ID: {action['id'][:8]}...")
    print(f"   Status: {action['status']}")
    print(f"   Decision: {action.get('decision')}")
    assert action['status'] == 'allowed', f"Expected allowed, got {action['status']}"
    results["allowed"] = True
    print("   ✅ ALLOWED status works")
    
    # Test 2: DENIED status (unknown tool)
    print("\n2. Testing DENIED status...")
    print("-" * 70)
    r = requests.post(f"{api_base}/v1/actions", json={
        "agent_id": "status-test",
        "tool": "unknown_tool",
        "operation": "dangerous_op",
        "params": {"destructive": True},
        "context": {}
    })
    action = r.json()
    print(f"   Action ID: {action['id'][:8]}...")
    print(f"   Status: {action['status']}")
    print(f"   Decision: {action.get('decision')}")
    print(f"   Reason: {action.get('reason')}")
    assert action['status'] == 'denied', f"Expected denied, got {action['status']}"
    results["denied"] = True
    print("   ✅ DENIED status works")
    
    # Test 3: PENDING_APPROVAL status (shell command)
    print("\n3. Testing PENDING_APPROVAL status...")
    print("-" * 70)
    r = requests.post(f"{api_base}/v1/actions", json={
        "agent_id": "status-test",
        "tool": "shell",
        "operation": "run",
        "params": {"cmd": "echo 'Hello FaraCore'"},
        "context": {}
    })
    action = r.json()
    pending_id = action['id']
    approval_token = action.get('approval_token')
    print(f"   Action ID: {pending_id[:8]}...")
    print(f"   Status: {action['status']}")
    print(f"   Decision: {action.get('decision')}")
    print(f"   Approval Token: {approval_token[:16] + '...' if approval_token else 'None'}")
    assert action['status'] == 'pending_approval', f"Expected pending_approval, got {action['status']}"
    assert approval_token is not None, "Missing approval token"
    results["pending_approval"] = True
    print("   ✅ PENDING_APPROVAL status works")
    
    # Test 4: APPROVED status
    print("\n4. Testing APPROVED status...")
    print("-" * 70)
    r = requests.post(f"{api_base}/v1/actions/{pending_id}/approval", json={
        "token": approval_token,
        "approve": True,
        "reason": "Test approval"
    })
    action = r.json()
    print(f"   Action ID: {action['id'][:8]}...")
    print(f"   Status: {action['status']}")
    assert action['status'] == 'approved', f"Expected approved, got {action['status']}"
    results["approved"] = True
    print("   ✅ APPROVED status works")
    
    # Test 5: EXECUTING status
    print("\n5. Testing EXECUTING status...")
    print("-" * 70)
    r = requests.post(f"{api_base}/v1/actions/{pending_id}/start")
    action = r.json()
    print(f"   Action ID: {action['id'][:8]}...")
    print(f"   Status: {action['status']}")
    assert action['status'] == 'executing', f"Expected executing, got {action['status']}"
    results["executing"] = True
    print("   ✅ EXECUTING status works")
    
    # Wait a bit for shell to complete
    time.sleep(2)
    
    # Test 6: SUCCEEDED status
    print("\n6. Testing SUCCEEDED status...")
    print("-" * 70)
    r = requests.get(f"{api_base}/v1/actions/{pending_id}")
    action = r.json()
    if action['status'] == 'succeeded':
        print(f"   Action ID: {action['id'][:8]}...")
        print(f"   Status: {action['status']}")
        print(f"   Reason: {action.get('reason', 'N/A')}")
        results["succeeded"] = True
        print("   ✅ SUCCEEDED status works (from executor)")
    else:
        # Manually report success
        r = requests.post(f"{api_base}/v1/actions/{pending_id}/result", json={
            "success": True,
            "error": None
        })
        action = r.json()
        print(f"   Action ID: {action['id'][:8]}...")
        print(f"   Status: {action['status']}")
        assert action['status'] == 'succeeded', f"Expected succeeded, got {action['status']}"
        results["succeeded"] = True
        print("   ✅ SUCCEEDED status works (from result endpoint)")
    
    # Test 7: FAILED status
    print("\n7. Testing FAILED status...")
    print("-" * 70)
    # Submit another shell command
    r = requests.post(f"{api_base}/v1/actions", json={
        "agent_id": "status-test",
        "tool": "shell",
        "operation": "run",
        "params": {"cmd": "nonexistent_command_xyz123"},
        "context": {}
    })
    action = r.json()
    fail_id = action['id']
    fail_token = action.get('approval_token')
    
    # Approve it
    if fail_token:
        requests.post(f"{api_base}/v1/actions/{fail_id}/approval", json={
            "token": fail_token,
            "approve": True
        })
        # Start execution
        requests.post(f"{api_base}/v1/actions/{fail_id}/start")
        time.sleep(2)
        
        # Report failure
        r = requests.post(f"{api_base}/v1/actions/{fail_id}/result", json={
            "success": False,
            "error": "Command not found: nonexistent_command_xyz123"
        })
        action = r.json()
        print(f"   Action ID: {action['id'][:8]}...")
        print(f"   Status: {action['status']}")
        print(f"   Reason: {action.get('reason', 'N/A')}")
        assert action['status'] == 'failed', f"Expected failed, got {action['status']}"
        results["failed"] = True
        print("   ✅ FAILED status works")
    
    # Test 8: List all actions and verify statuses
    print("\n8. Testing action listing with all statuses...")
    print("-" * 70)
    r = requests.get(f"{api_base}/v1/actions?limit=50")
    assert r.status_code == 200, f"List failed: {r.status_code}"
    actions = r.json()
    
    statuses_found = set(a['status'] for a in actions)
    print(f"   Found {len(actions)} actions")
    print(f"   Statuses present: {', '.join(sorted(statuses_found))}")
    
    # Verify we have the key statuses
    required_statuses = {'allowed', 'denied', 'pending_approval', 'approved', 'executing', 'succeeded', 'failed'}
    found_required = required_statuses.intersection(statuses_found)
    print(f"   Required statuses found: {len(found_required)}/{len(required_statuses)}")
    print(f"   Missing: {required_statuses - found_required}")
    
    # Test 9: Filter by status
    print("\n9. Testing status filters...")
    print("-" * 70)
    for status in ['allowed', 'denied', 'pending_approval', 'succeeded', 'failed']:
        r = requests.get(f"{api_base}/v1/actions?status={status}&limit=10")
        if r.status_code == 200:
            filtered = r.json()
            print(f"   {status}: {len(filtered)} actions")
    
    # Test 10: UI endpoint
    print("\n10. Testing UI endpoint...")
    print("-" * 70)
    r = requests.get(f"{api_base}/")
    if r.status_code == 200 and "FaraCore" in r.text:
        print("   ✅ UI loads correctly")
    else:
        print(f"   ⚠️  UI returned {r.status_code}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    for status, passed in results.items():
        status_icon = "✅" if passed else "❌"
        print(f"   {status_icon} {status.upper()}: {'PASS' if passed else 'FAIL'}")
    
    all_passed = all(results.values())
    print("\n" + "=" * 70)
    if all_passed:
        print("✅ ALL STATUS TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)
    print("=" * 70)

def main():
    """Run comprehensive tests."""
    api_base = find_server()
    if not api_base:
        print("❌ Server not running. Start with: faracore serve")
        sys.exit(1)
    
    print(f"✅ Using server at {api_base}\n")
    
    try:
        test_all_statuses(api_base)
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

if __name__ == "__main__":
    main()
