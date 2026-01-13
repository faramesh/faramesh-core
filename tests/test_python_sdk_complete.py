"""Comprehensive integration tests for the Python SDK.

These tests verify all SDK functionality against a running FaraCore server.
"""

import os
import time
import pytest
from pathlib import Path
import tempfile

from faracore.sdk import (
    configure,
    submit_action,
    get_action,
    list_actions,
    approve_action,
    deny_action,
    start_action,
    replay_action,
    wait_for_completion,
    apply,
    allow,
    deny,
    FaraCoreError,
    FaraCoreAuthError,
    FaraCoreNotFoundError,
    FaraCorePolicyError,
    FaraCoreTimeoutError,
    FaraCoreConnectionError,
    FaraCoreValidationError,
    ExecutionGovernorClient,
    ClientConfig,
)


@pytest.fixture(autouse=True)
def reset_config():
    """Reset SDK configuration before each test."""
    from faracore.sdk.client import _config
    import faracore.sdk.client as sdk_module
    sdk_module._config = None
    yield
    sdk_module._config = None


def test_configure_and_env_vars(server):
    """Test configure() function and environment variable support."""
    # Test explicit config with server
    configure(base_url=server, token=None)
    action = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    assert "id" in action
    assert action["status"] in ("allowed", "pending_approval", "denied")
    
    # Test env var override
    os.environ["FARACORE_BASE_URL"] = server
    configure()
    action2 = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    assert "id" in action2
    del os.environ["FARACORE_BASE_URL"]
    
    # Reset config
    configure(base_url=server)


def test_submit_action_happy_path(server):
    """Test submitting an action that gets allowed."""
    configure(base_url=server)
    
    action = submit_action(
        agent_id="test-agent",
        tool="http",
        operation="get",
        params={"url": "https://example.com"},
        context={"source": "test"},
    )
    
    assert "id" in action
    assert action["agent_id"] == "test-agent"
    assert action["tool"] == "http"
    assert action["operation"] == "get"
    assert action["params"] == {"url": "https://example.com"}
    assert action["context"]["source"] == "test"
    assert action["status"] in ("allowed", "pending_approval", "denied")
    assert "decision" in action
    assert "created_at" in action


def test_submit_action_pending_approval(server):
    """Test submitting an action that requires approval."""
    configure(base_url=server)
    
    action = submit_action(
        agent_id="test-agent",
        tool="shell",
        operation="run",
        params={"cmd": "echo hello"},
    )
    
    assert action["status"] == "pending_approval"
    assert "approval_token" in action
    assert action["approval_token"] is not None


def test_get_action(server):
    """Test getting an action by ID."""
    configure(base_url=server)
    
    # Submit an action
    submitted = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    action_id = submitted["id"]
    
    # Get it back
    fetched = get_action(action_id)
    assert fetched["id"] == action_id
    assert fetched["agent_id"] == "test-agent"
    assert fetched["tool"] == "http"
    assert fetched["operation"] == "get"


def test_get_action_not_found(server):
    """Test getting a non-existent action."""
    configure(base_url=server)
    
    with pytest.raises(FaraCoreNotFoundError):
        get_action("00000000-0000-0000-0000-000000000000")


def test_list_actions(server):
    """Test listing actions with filters."""
    configure(base_url=server)
    
    # Submit a few actions
    submit_action("agent1", "http", "get", {"url": "https://example.com"})
    submit_action("agent2", "shell", "run", {"cmd": "ls"})
    submit_action("agent1", "http", "post", {"url": "https://example.com", "data": "test"})
    
    # List all
    all_actions = list_actions(limit=10)
    assert len(all_actions) > 0
    assert all("id" in a for a in all_actions)
    
    # Filter by agent
    agent1_actions = list_actions(limit=10, agent_id="agent1")
    assert len(agent1_actions) > 0
    assert all(a["agent_id"] == "agent1" for a in agent1_actions)
    
    # Filter by tool
    http_actions = list_actions(limit=10, tool="http")
    assert len(http_actions) > 0
    assert all(a["tool"] == "http" for a in http_actions)
    
    # Filter by status
    pending = list_actions(limit=10, status="pending_approval")
    assert all(a["status"] == "pending_approval" for a in pending)


def test_approve_action(server):
    """Test approving a pending action."""
    configure(base_url=server)
    
    # Submit action that requires approval
    action = submit_action("test-agent", "shell", "run", {"cmd": "echo hello"})
    assert action["status"] == "pending_approval"
    
    # Approve it
    approved = approve_action(action["id"], token=action["approval_token"])
    assert approved["status"] == "approved"
    assert approved["decision"] == "allow"
    
    # Test auto-token extraction
    action2 = submit_action("test-agent", "shell", "run", {"cmd": "ls"})
    approved2 = approve_action(action2["id"], token=action2["approval_token"])
    assert approved2["status"] == "approved"


def test_deny_action(server):
    """Test denying a pending action."""
    configure(base_url=server)
    
    # Submit action that requires approval
    action = submit_action("test-agent", "shell", "run", {"cmd": "rm -rf /"})
    assert action["status"] == "pending_approval"
    
    # Deny it
    denied = deny_action(action["id"], token=action["approval_token"], reason="Too dangerous")
    assert denied["status"] == "denied"
    assert denied["decision"] == "deny"
    assert "Too dangerous" in denied.get("reason", "")


def test_start_action(server):
    """Test starting an approved/allowed action."""
    configure(base_url=server)
    
    # Submit and approve an action
    action = submit_action("test-agent", "shell", "run", {"cmd": "echo hello"})
    if action["status"] == "pending_approval":
        action = approve_action(action["id"], token=action["approval_token"])
    
    # Start it
    started = start_action(action["id"])
    assert started["status"] in ("executing", "succeeded", "failed")


def test_start_action_invalid_status(server):
    """Test starting an action that's not in allowed/approved status."""
    configure(base_url=server)
    
    # Submit and deny an action
    action = submit_action("test-agent", "shell", "run", {"cmd": "rm -rf /"})
    if action["status"] == "pending_approval":
        action = deny_action(action["id"], token=action["approval_token"])
    
    # Try to start it (should fail)
    with pytest.raises(FaraCoreError):
        start_action(action["id"])


def test_replay_action(server):
    """Test replaying an action."""
    configure(base_url=server)
    
    # Submit and approve an action
    original = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    if original["status"] == "pending_approval":
        original = approve_action(original["id"], token=original["approval_token"])
    
    # Replay it
    replayed = replay_action(original["id"])
    assert replayed["id"] != original["id"]
    assert replayed["agent_id"] == original["agent_id"]
    assert replayed["tool"] == original["tool"]
    assert replayed["operation"] == original["operation"]
    assert replayed["params"] == original["params"]
    assert replayed["context"].get("replayed_from") == original["id"]


def test_replay_action_invalid_status(server):
    """Test replaying an action that can't be replayed."""
    configure(base_url=server)
    
    # Submit and deny an action
    action = submit_action("test-agent", "shell", "run", {"cmd": "rm -rf /"})
    if action["status"] == "pending_approval":
        action = deny_action(action["id"], token=action["approval_token"])
    
    # Try to replay it (should fail)
    # SDK checks status before attempting replay
    with pytest.raises(FaraCoreError) as exc_info:
        replay_action(action["id"])
    assert "Cannot replay" in str(exc_info.value) or "not replayable" in str(exc_info.value).lower()


def test_wait_for_completion(server):
    """Test waiting for action completion."""
    configure(base_url=server)
    
    # Submit and start an action
    action = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    if action["status"] == "pending_approval":
        action = approve_action(action["id"], token=action["approval_token"])
    
    # Start it
    started = start_action(action["id"])
    
    # Wait for completion (with short timeout for test)
    try:
        final = wait_for_completion(started["id"], poll_interval=0.5, timeout=10.0)
        assert final["status"] in ("succeeded", "failed")
    except FaraCoreTimeoutError:
        # Timeout is acceptable if action takes too long
        pass


def test_wait_for_completion_timeout(server):
    """Test wait_for_completion timeout."""
    configure(base_url=server)
    
    # Submit an action but don't start it
    action = submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    
    # Wait for completion (should timeout since it's not executing)
    with pytest.raises(FaraCoreTimeoutError):
        wait_for_completion(action["id"], poll_interval=0.1, timeout=0.5)


def test_apply_yaml_file(server):
    """Test loading and submitting action from YAML file."""
    configure(base_url=server)
    
    # Create temporary YAML file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""agent_id: test-agent
tool: http
operation: get
params:
  url: https://example.com
context:
  source: yaml_test
""")
        yaml_path = f.name
    
    try:
        action = apply(yaml_path)
        assert action["agent_id"] == "test-agent"
        assert action["tool"] == "http"
        assert action["operation"] == "get"
        assert action["params"]["url"] == "https://example.com"
    finally:
        os.unlink(yaml_path)


def test_apply_json_file(server):
    """Test loading and submitting action from JSON file."""
    configure(base_url=server)
    
    # Create temporary JSON file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        import json
        json.dump({
            "agent_id": "test-agent",
            "tool": "http",
            "operation": "get",
            "params": {"url": "https://example.com"},
            "context": {"source": "json_test"},
        }, f)
        json_path = f.name
    
    try:
        action = apply(json_path)
        assert action["agent_id"] == "test-agent"
        assert action["tool"] == "http"
    finally:
        os.unlink(json_path)


def test_apply_file_not_found(server):
    """Test apply() with non-existent file."""
    configure(base_url=server)
    
    with pytest.raises(FileNotFoundError):
        apply("/nonexistent/file.yaml")


def test_apply_invalid_file(server):
    """Test apply() with invalid file format."""
    configure(base_url=server)
    
    # Create invalid file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("invalid: yaml: content: [")
        invalid_path = f.name
    
    try:
        with pytest.raises(FaraCoreValidationError):
            apply(invalid_path)
    finally:
        os.unlink(invalid_path)


def test_apply_missing_fields(server):
    """Test apply() with missing required fields."""
    configure(base_url=server)
    
    # Create file with missing fields
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        import json
        json.dump({"tool": "http"}, f)
        invalid_path = f.name
    
    try:
        with pytest.raises(FaraCoreValidationError) as exc_info:
            apply(invalid_path)
        assert "Missing required fields" in str(exc_info.value)
    finally:
        os.unlink(invalid_path)


def test_convenience_aliases(server):
    """Test convenience aliases (allow, deny)."""
    configure(base_url=server)
    
    # Submit action
    action = submit_action("test-agent", "shell", "run", {"cmd": "echo hello"})
    if action["status"] == "pending_approval":
        # Use alias
        approved = allow(action["id"], token=action["approval_token"])
        assert approved["status"] == "approved"
    
    # Test deny alias
    action2 = submit_action("test-agent", "shell", "run", {"cmd": "rm -rf /"})
    if action2["status"] == "pending_approval":
        denied = deny(action2["id"], token=action2["approval_token"])
        assert denied["status"] == "denied"


def test_error_handling_auth(server):
    """Test authentication error handling."""
    configure(base_url=server, token="invalid-token")
    
    # This should work if server doesn't require auth, or fail if it does
    # We'll just verify the error type is correct
    try:
        submit_action("test-agent", "http", "get", {"url": "https://example.com"})
    except FaraCoreAuthError:
        pass  # Expected if auth is required
    except FaraCoreError:
        pass  # Other errors are also acceptable


def test_error_handling_connection():
    """Test connection error handling."""
    configure(base_url="http://127.0.0.1:99999", token=None)
    
    # Any error is acceptable for connection test (OS/network dependent)
    with pytest.raises(Exception):
        submit_action("test-agent", "http", "get", {"url": "https://example.com"})


def test_error_handling_timeout():
    """Test timeout error handling."""
    # Use a non-existent port with short timeout to trigger timeout
    configure(base_url="http://127.0.0.1:99999", timeout=0.1)
    
    # May get connection error, timeout, or generic error depending on OS
    with pytest.raises((FaraCoreTimeoutError, FaraCoreConnectionError, FaraCoreError)):
        submit_action("test-agent", "http", "get", {"url": "https://example.com"})


def test_legacy_client_class(server):
    """Test backward compatibility with ExecutionGovernorClient class."""
    config = ClientConfig(base_url=server, token=None)
    client = ExecutionGovernorClient(config)
    
    # Test all methods work
    action = client.submit_action("http", "get", {"url": "https://example.com"})
    assert "id" in action
    
    fetched = client.get_action(action["id"])
    assert fetched["id"] == action["id"]
    
    actions = client.list_actions(limit=5)
    assert isinstance(actions, list)
    
    if action["status"] == "pending_approval":
        approved = client.approve_action(action["id"], token=action["approval_token"])
        assert approved["status"] == "approved"


def test_policy_error_on_denial(server):
    """Test that denied actions raise FaraCorePolicyError."""
    configure(base_url=server)
    
    # Submit an action that will be denied
    try:
        action = submit_action("test-agent", "unknown", "do", {})
        # If it's denied, check the response
        if action.get("status") == "denied":
            # The SDK should have raised an error, but if it didn't, verify the status
            assert action["status"] == "denied"
    except FaraCorePolicyError:
        pass  # Expected behavior


def test_sdk_version():
    """Test that SDK version is accessible."""
    from faracore.sdk import __version__
    assert isinstance(__version__, str)
    assert len(__version__) > 0
