"""Tests for ``faramesh.callbacks`` (lifecycle stream subscription)."""

from __future__ import annotations

import time

import pytest

from faramesh import callbacks


def test_subscribe_sends_callback_subscribe_request(socket_path, start_mock_server):
    """The wire request is ``{"type":"callback_subscribe"}`` (no agent_id field).

    The daemon's callback_subscribe handler ignores agent_id, so the
    wrapper omits the field entirely from the request.
    """
    events = [
        {
            "event_type": "defer_resolved",
            "defer_token": "abc123",
            "status": "approved",
            "approved": True,
            "approver_id": "alice",
            "reason": "looks good",
        }
    ]
    server, captured = start_mock_server(
        socket_path,
        events,
        confirmation=b'{"subscribed": true, "stream": "callbacks"}\n',
    )

    received: list[dict] = []
    sub = callbacks.subscribe(received.append, socket_path=socket_path)

    deadline = time.time() + 2.0
    while time.time() < deadline and not received:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert captured == [{"type": "callback_subscribe"}]
    assert len(received) == 1
    assert received[0]["event_type"] == "defer_resolved"
    assert received[0]["defer_token"] == "abc123"
    assert received[0]["status"] == "approved"


def test_subscribe_receives_lifecycle_events(socket_path, start_mock_server):
    """Multiple lifecycle events flow through the callback in order."""
    events = [
        {
            "event_type": "defer_resolved",
            "defer_token": "tok-1",
            "status": "approved",
            "approved": True,
            "approver_id": "alice",
        },
        {
            "event_type": "defer_resolved",
            "defer_token": "tok-2",
            "status": "denied",
            "approved": False,
            "approver_id": "bob",
        },
    ]
    server, _captured = start_mock_server(
        socket_path,
        events,
        confirmation=b'{"subscribed": true, "stream": "callbacks"}\n',
    )

    received: list[dict] = []
    sub = callbacks.subscribe(received.append, socket_path=socket_path)

    deadline = time.time() + 2.0
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.02)
    sub.close()
    server.join(timeout=2.0)

    assert len(received) == 2
    assert received[0]["status"] == "approved"
    assert received[1]["status"] == "denied"


def test_subscribe_context_manager(socket_path, start_mock_server):
    """``with`` form opens and closes cleanly."""
    events = [{"event_type": "defer_resolved", "defer_token": "t", "status": "approved"}]
    server, _captured = start_mock_server(
        socket_path,
        events,
        confirmation=b'{"subscribed": true, "stream": "callbacks"}\n',
    )

    received: list[dict] = []
    with callbacks.subscribe(received.append, socket_path=socket_path) as sub:
        assert isinstance(sub, callbacks.Subscription)
        deadline = time.time() + 2.0
        while time.time() < deadline and not received:
            time.sleep(0.02)

    server.join(timeout=2.0)
    assert len(received) == 1


def test_subscribe_raises_when_socket_missing():
    """Connecting to a nonexistent socket fails fast."""
    with pytest.raises(ConnectionError):
        callbacks.subscribe(lambda _: None, socket_path="/nonexistent/faramesh.sock")
