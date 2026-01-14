import json
import time
from uuid import uuid4

import httpx


def test_health_ready(server):
    with httpx.Client(base_url=server, timeout=5.0) as client:
        r = client.get("/health")
        assert r.status_code == 200
        r = client.get("/ready")
        assert r.status_code == 200


def test_allow_and_deny(server):
    with httpx.Client(base_url=server, timeout=5.0) as client:
        # Allow (http)
        r = client.post(
            "/v1/actions",
            json={"agent_id": "a1", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
        )
        assert r.status_code == 200
        allowed = r.json()
        assert allowed["status"] == "allowed"

        # Deny (unknown)
        r = client.post(
            "/v1/actions",
            json={"agent_id": "a2", "tool": "unknown", "operation": "do", "params": {}},
        )
        assert r.status_code == 200
        denied = r.json()
        assert denied["status"] == "denied"
        assert denied["decision"] == "deny"


def test_action_response_includes_sdk_examples(server):
    """Every action response exposes js_example and python_example for DX."""
    with httpx.Client(base_url=server, timeout=5.0) as client:
        r = client.post(
            "/v1/actions",
            json={
                "agent_id": "sdk-test",
                "tool": "http",
                "operation": "get",
                "params": {"url": "https://example.com"},
            },
        )
        assert r.status_code == 200
        action = r.json()
        # Fields are present and non-empty strings
        assert "js_example" in action
        assert "python_example" in action
        assert isinstance(action["js_example"], str)
        assert isinstance(action["python_example"], str)


def test_events_endpoint(server):
    """Test the events API endpoint."""
    with httpx.Client(base_url=server, timeout=10.0) as client:
        # Create an action
        r = client.post(
            "/v1/actions",
            json={"agent_id": "test", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
        )
        assert r.status_code == 200
        action = r.json()
        action_id = action["id"]
        
        # Get events
        r = client.get(f"/v1/actions/{action_id}/events")
        assert r.status_code == 200
        events = r.json()
        assert isinstance(events, list)
        # Should have at least "created" and "decision_made" events
        event_types = [e["event_type"] for e in events]
        assert "created" in event_types
        assert "decision_made" in event_types


def test_require_approval_flow(server):
    with httpx.Client(base_url=server, timeout=10.0) as client:
        # Submit requires approval
        r = client.post(
            "/v1/actions",
            json={"agent_id": "agent-approve", "tool": "shell", "operation": "run", "params": {"cmd": "echo hi"}},
        )
        assert r.status_code == 200
        action = r.json()
        assert action["status"] == "pending_approval"
        token = action["approval_token"]

        # Approve
        r = client.post(
            f"/v1/actions/{action['id']}/approval",
            json={"token": token, "approve": True},
        )
        assert r.status_code == 200
        approved = r.json()
        assert approved["status"] == "approved"

        # Start execution
        r = client.post(f"/v1/actions/{action['id']}/start")
        assert r.status_code == 200
        started = r.json()
        assert started["status"] in ("executing", "succeeded")

        # Wait for completion
        time.sleep(1.5)
        r = client.get(f"/v1/actions/{action['id']}")
        final = r.json()
        assert final["status"] in ("succeeded", "failed")


def test_missing_token_and_invalid_token(auth_server):
    # Missing token
    with httpx.Client(base_url=auth_server, timeout=5.0) as client:
        r = client.get("/v1/actions")
        assert r.status_code == 401

    # With token works
    headers = {"Authorization": "Bearer secret-token"}
    with httpx.Client(base_url=auth_server, timeout=5.0, headers=headers) as client:
        r = client.get("/v1/actions")
        assert r.status_code == 200

        # Invalid approval token
        r = client.post(
            "/v1/actions",
            json={"agent_id": "agent", "tool": "shell", "operation": "run", "params": {"cmd": "echo hi"}},
        )
        action = r.json()
        bad = client.post(
            f"/v1/actions/{action['id']}/approval",
            json={"token": "bad-token", "approve": True},
        )
        assert bad.status_code == 401


def test_unknown_id_and_malformed_request(server):
    with httpx.Client(base_url=server, timeout=5.0) as client:
        unknown_id = str(uuid4())
        r = client.get(f"/v1/actions/{unknown_id}")
        assert r.status_code == 404

        # Missing required fields -> validation error
        r = client.post("/v1/actions", json={"tool": "http"})
        assert r.status_code == 422


def test_metrics_and_sse(server):
    with httpx.Client(base_url=server, timeout=10.0) as client:
        # Start SSE stream
        with client.stream("GET", "/v1/events", timeout=10.0) as stream:
            # Trigger action
            client.post(
                "/v1/actions",
                json={"agent_id": "sse", "tool": "http", "operation": "get", "params": {"url": "https://example.com"}},
            )
            found_event = False
            for line in stream.iter_lines():
                if not line:
                    continue
                if line.startswith("data:"):
                    data = json.loads(line.replace("data:", "").strip())
                    assert data["type"].startswith("action.")
                    found_event = True
                    break
            assert found_event

        # Metrics should include actions_total
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "actions_total" in r.text

