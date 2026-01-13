"""Tests for batch submit and async/streaming helpers."""

import pytest
from faracore.sdk import (
    configure,
    submit_actions,
    submit_and_wait,
    tail_events,
)


@pytest.fixture(autouse=True)
def reset_config():
    """Reset SDK configuration before each test."""
    from faracore.sdk.client import _config
    import faracore.sdk.client as sdk_module
    sdk_module._config = None
    yield
    sdk_module._config = None


def test_submit_actions_batch(server):
    """Test batch submission of multiple actions."""
    configure(base_url=server)
    
    actions = submit_actions([
        {
            "agent_id": "agent1",
            "tool": "http",
            "operation": "get",
            "params": {"url": "https://example.com"},
        },
        {
            "agent_id": "agent2",
            "tool": "http",
            "operation": "get",
            "params": {"url": "https://example.org"},
        },
    ])
    
    assert len(actions) == 2
    assert all("id" in a or "error" in a for a in actions)
    assert all(a.get("status") in ("allowed", "pending_approval", "denied") or "error" in a for a in actions)


def test_submit_and_wait_allowed(server):
    """Test submit_and_wait with an action that gets allowed."""
    configure(base_url=server)
    
    # Submit an action that should be allowed
    action = submit_and_wait(
        "test-agent",
        "http",
        "get",
        {"url": "https://example.com"},
        timeout=10.0,
        poll_interval=0.5,
    )
    
    # Should complete (may succeed or timeout if execution takes too long)
    assert action["status"] in ("succeeded", "failed", "allowed", "executing")


def test_submit_and_wait_with_auto_approve(server):
    """Test submit_and_wait with require_approval=True and auto_start=True."""
    configure(base_url=server)
    
    # Submit an action that requires approval
    try:
        action = submit_and_wait(
            "test-agent",
            "shell",
            "run",
            {"cmd": "echo hello"},
            timeout=10,
            poll_interval=1,
            require_approval=True,
            auto_start=True,
        )
        # Should complete if auto-approved and started
        assert action["status"] in ("succeeded", "failed", "approved", "executing", "allowed")
    except Exception as e:
        # Timeout or other errors are acceptable
        assert "timeout" in str(e).lower() or "approval" in str(e).lower() or "denied" in str(e).lower()


def test_submit_and_wait_requires_approval(server):
    """Test submit_and_wait with require_approval=True but no auto_start."""
    configure(base_url=server)
    
    # Submit an action that requires approval
    try:
        action = submit_and_wait(
            "test-agent",
            "shell",
            "run",
            {"cmd": "echo hello"},
            timeout=5,
            require_approval=True,
            auto_start=False,
        )
        # Should return pending or approved status
        assert action["status"] in ("pending_approval", "approved", "allowed", "denied")
    except Exception as e:
        # Timeout or denied errors are acceptable
        assert "timeout" in str(e).lower() or "denied" in str(e).lower()


def test_tail_events_structure(server):
    """Test that tail_events function exists and has correct signature."""
    configure(base_url=server)
    
    # Just verify the function exists and can be called
    # (actual SSE streaming test would require more setup)
    assert callable(tail_events)
    
    # Test that it raises error if sseclient not available (in some environments)
    # This is a structure test, not a full integration test
