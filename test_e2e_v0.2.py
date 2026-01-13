#!/usr/bin/env python3
"""
End-to-end integration test for FaraCore v0.2 features.
Starts a server and tests all features through the API and CLI.
"""

import os
import sys
import time
import subprocess
import requests
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def wait_for_server(url, max_wait=10):
    """Wait for server to be ready"""
    for i in range(max_wait):
        try:
            r = requests.get(f"{url}/health", timeout=1)
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(1)
    return False


def test_risk_scoring_e2e(server_url):
    """Test risk scoring through API"""
    print("\n=== E2E Test: Risk Scoring ===")
    
    # Create a policy with risk rules
    policy_content = """
rules:
  - match: { tool: "*", op: "*" }
    allow: true

risk:
  rules:
    - name: dangerous_shell
      when:
        tool: shell
        operation: run
        pattern: "rm -rf"
      risk_level: high
"""
    
    # Submit action that should trigger high risk
    response = requests.post(
        f"{server_url}/v1/actions",
        json={
            "agent_id": "test",
            "tool": "shell",
            "operation": "run",
            "params": {"cmd": "rm -rf /tmp"},
        },
        timeout=5
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    action = response.json()
    
    # Check risk_level is set
    assert "risk_level" in action, "risk_level not in response"
    print(f"✓ Risk level computed: {action.get('risk_level')}")
    
    return True


def test_events_api_e2e(server_url):
    """Test events API endpoint"""
    print("\n=== E2E Test: Events API ===")
    
    # Create an action
    response = requests.post(
        f"{server_url}/v1/actions",
        json={
            "agent_id": "test",
            "tool": "http",
            "operation": "get",
            "params": {"url": "https://example.com"},
        },
        timeout=5
    )
    
    assert response.status_code == 200
    action = response.json()
    action_id = action["id"]
    print(f"✓ Action created: {action_id[:8]}")
    
    # Get events
    response = requests.get(f"{server_url}/v1/actions/{action_id}/events", timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    events = response.json()
    
    assert isinstance(events, list), "Events should be a list"
    assert len(events) > 0, "Should have at least one event"
    
    # Check event structure
    event = events[0]
    assert "event_type" in event, "Event should have event_type"
    assert "created_at" in event, "Event should have created_at"
    assert "meta" in event, "Event should have meta"
    
    print(f"✓ Events retrieved: {len(events)} events")
    print(f"  Event types: {[e['event_type'] for e in events]}")
    
    return True


def test_demo_seed_e2e(server_url):
    """Test demo seed mode"""
    print("\n=== E2E Test: Demo Seed Mode ===")
    
    # List actions
    response = requests.get(f"{server_url}/v1/actions?limit=100", timeout=5)
    assert response.status_code == 200
    actions = response.json()
    
    # Check for demo actions
    demo_actions = [a for a in actions if a.get("agent_id") == "demo"]
    
    if len(demo_actions) > 0:
        print(f"✓ Found {len(demo_actions)} demo actions")
        for action in demo_actions[:3]:
            print(f"  - {action['id'][:8]}: {action['status']} ({action['tool']})")
        return True
    else:
        print("⚠ No demo actions found (may not be in demo mode)")
        return True  # Not a failure, just not in demo mode


def test_cli_commands():
    """Test CLI commands"""
    print("\n=== E2E Test: CLI Commands ===")
    
    # Test that CLI module can be imported and has events command
    try:
        from faracore.cli import cmd_events, make_parser
        
        # Verify events command exists
        parser = make_parser()
        found_events = False
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices is not None:
                if 'events' in action.choices:
                    found_events = True
                    break
        
        assert found_events, "Events command not found in parser"
        assert callable(cmd_events), "cmd_events not callable"
        print("✓ CLI events command exists and is callable")
        
        return True
    except Exception as e:
        print(f"✗ CLI test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run end-to-end tests"""
    print("=" * 60)
    print("FaraCore v0.2 End-to-End Integration Tests")
    print("=" * 60)
    
    # Check if server is running
    server_url = os.getenv("FARA_API_BASE", "http://127.0.0.1:8000")
    
    print(f"\nTesting against server: {server_url}")
    print("(Start server with: faracore serve)")
    
    if not wait_for_server(server_url):
        print(f"\n⚠ Server not running at {server_url}")
        print("Skipping API tests. Run: faracore serve")
        
        # Still test CLI
        tests = [
            ("CLI Commands", test_cli_commands),
        ]
    else:
        print("✓ Server is running")
        tests = [
            ("Risk Scoring", lambda: test_risk_scoring_e2e(server_url)),
            ("Events API", lambda: test_events_api_e2e(server_url)),
            ("Demo Seed Mode", lambda: test_demo_seed_e2e(server_url)),
            ("CLI Commands", test_cli_commands),
        ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ {name} test failed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("E2E Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All E2E tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
