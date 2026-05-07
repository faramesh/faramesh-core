"""Tests for ``faramesh.audit`` (decision stream subscription)."""

from __future__ import annotations

import time

import pytest

from faramesh import audit


def test_subscribe_sends_audit_subscribe_request(socket_path, start_mock_server):
    """The wire request is ``{"type":"audit_subscribe","agent_id":""}``."""
    events = [
        {"effect": "PERMIT", "agent_id": "bot", "tool_id": "t1", "record_id": "r1"},
    ]
    server, captured = start_mock_server(socket_path, events)

    received: list[dict] = []
    sub = audit.subscribe(received.append, socket_path=socket_path)
    deadline = time.time() + 2.0
    while time.time() < deadline and not received:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert captured == [{"type": "audit_subscribe", "agent_id": ""}]


def test_subscribe_receives_events(socket_path, start_mock_server):
    """Callback fires once per event with the parsed dict."""
    events = [
        {"effect": "PERMIT", "agent_id": "bot", "tool_id": "t1", "record_id": "r1"},
        {"effect": "DENY", "agent_id": "bot", "tool_id": "t2", "record_id": "r2"},
    ]
    server, _captured = start_mock_server(socket_path, events)

    received: list[dict] = []
    sub = audit.subscribe(received.append, socket_path=socket_path)

    deadline = time.time() + 2.0
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert len(received) == 2
    assert received[0]["effect"] == "PERMIT"
    assert received[0]["record_id"] == "r1"
    assert received[1]["effect"] == "DENY"
    assert received[1]["record_id"] == "r2"


def test_subscribe_filters_by_agent_id(socket_path, start_mock_server):
    """When agent_id is provided, events for other agents are dropped."""
    events = [
        {"effect": "PERMIT", "agent_id": "bot-a", "tool_id": "t1"},
        {"effect": "PERMIT", "agent_id": "bot-b", "tool_id": "t2"},
        {"effect": "PERMIT", "agent_id": "bot-a", "tool_id": "t3"},
    ]
    server, captured = start_mock_server(socket_path, events)

    received: list[dict] = []
    sub = audit.subscribe(received.append, socket_path=socket_path, agent_id="bot-a")

    deadline = time.time() + 2.0
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert captured == [{"type": "audit_subscribe", "agent_id": "bot-a"}]
    assert len(received) == 2
    assert all(e["agent_id"] == "bot-a" for e in received)


def test_subscribe_context_manager(socket_path, start_mock_server):
    """``with`` form opens and closes cleanly."""
    events = [{"effect": "PERMIT", "agent_id": "bot", "tool_id": "t1"}]
    server, _captured = start_mock_server(socket_path, events)

    received: list[dict] = []
    with audit.subscribe(received.append, socket_path=socket_path) as sub:
        assert isinstance(sub, audit.Subscription)
        deadline = time.time() + 2.0
        while time.time() < deadline and not received:
            time.sleep(0.02)

    server.join(timeout=2.0)
    assert len(received) == 1


def test_subscribe_raises_when_socket_missing():
    """Connecting to a nonexistent socket fails fast."""
    with pytest.raises(ConnectionError):
        audit.subscribe(lambda _: None, socket_path="/nonexistent/faramesh.sock")


def test_callback_exception_does_not_kill_subscription(socket_path, start_mock_server):
    """A raising callback is logged but the stream keeps running."""
    events = [
        {"effect": "PERMIT", "agent_id": "bot", "tool_id": "t1"},
        {"effect": "PERMIT", "agent_id": "bot", "tool_id": "t2"},
    ]
    server, _captured = start_mock_server(socket_path, events)

    received: list[dict] = []

    def callback(event: dict) -> None:
        received.append(event)
        if len(received) == 1:
            raise RuntimeError("intentional test failure")

    sub = audit.subscribe(callback, socket_path=socket_path)

    deadline = time.time() + 2.0
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert len(received) == 2  # second event still delivered
