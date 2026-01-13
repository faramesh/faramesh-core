#!/usr/bin/env python3
"""Smoke test for FaraCore - basic functionality test."""

import sys
import time
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from faracore.sdk import ExecutionGovernorClient

API_BASE = None  # Will be set in main()

def test_submit_action(api_base):
    """Test submitting an action."""
    print("🧪 Test 1: Submit action...")
    client = ExecutionGovernorClient(api_base)
    
    response = client.submit_action(
        tool="shell",
        operation="run",
        params={"cmd": "echo 'test'"},
        context={"test": True}
    )
    
    assert "id" in response
    assert "status" in response
    print(f"✅ Action submitted: {response['id']} - Status: {response['status']}")
    return response["id"]

def test_get_action(action_id, api_base):
    """Test getting an action."""
    print(f"🧪 Test 2: Get action {action_id}...")
    client = ExecutionGovernorClient(api_base)
    
    action = client.get_action(action_id)
    assert action["id"] == action_id
    print(f"✅ Action retrieved: {action['status']}")

def test_list_actions(api_base):
    """Test listing actions."""
    print("🧪 Test 3: List actions...")
    client = ExecutionGovernorClient(api_base)
    
    actions = client.list_actions(limit=10)
    assert isinstance(actions, list)
    print(f"✅ Listed {len(actions)} actions")

def test_approve_action(action_id, api_base):
    """Test approving an action (if pending)."""
    print(f"🧪 Test 4: Approve action {action_id}...")
    client = ExecutionGovernorClient(api_base)
    
    action = client.get_action(action_id)
    if action["status"] == "pending_approval" and action.get("approval_token"):
        response = requests.post(
            f"{api_base}/v1/actions/{action_id}/approval",
            json={
                "token": action["approval_token"],
                "approve": True
            }
        )
        if response.ok:
            print("✅ Action approved")
        else:
            print(f"⚠️  Approval failed: {response.status_code}")
    else:
        print(f"⚠️  Action not pending approval (status: {action['status']})")

def test_health(api_base):
    """Test health endpoint."""
    print("🧪 Test 5: Health check...")
    response = requests.get(f"{api_base}/health")
    assert response.status_code == 200
    print("✅ Health check passed")

def test_metrics(api_base):
    """Test metrics endpoint."""
    print("🧪 Test 6: Metrics endpoint...")
    response = requests.get(f"{api_base}/metrics")
    assert response.status_code == 200
    print("✅ Metrics endpoint working")

def main():
    """Run all smoke tests."""
    print("🚀 Starting FaraCore smoke tests...\n")
    
    # Try multiple ports
    ports = [8000, 8001, 8002]
    api_base = None
    
    for port in ports:
        try:
            test_url = f"http://127.0.0.1:{port}"
            requests.get(f"{test_url}/health", timeout=1)
            api_base = test_url
            print(f"✅ Found server on port {port}\n")
            break
        except requests.exceptions.ConnectionError:
            continue
    
    if not api_base:
        print("❌ Server not running. Start with: faracore serve")
        print("   Or set FARA_API_BASE environment variable")
        sys.exit(1)
    
    try:
        test_health(api_base)
        test_metrics(api_base)
        action_id = test_submit_action(api_base)
        time.sleep(0.5)  # Small delay
        test_get_action(action_id, api_base)
        test_list_actions(api_base)
        test_approve_action(action_id, api_base)
        
        print("\n✅ All smoke tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
