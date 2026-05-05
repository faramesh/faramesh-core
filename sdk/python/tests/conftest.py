"""Shared fixtures and helpers for socket-stream subscription tests.

A real Faramesh daemon isn't available in unit tests, so we stand up a
mock Unix-socket server in a thread that mimics the daemon's
subscribe-style protocols: read one newline-delimited JSON request,
write a confirmation, then write canned events.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time

import pytest


def _mock_subscribe_server(
    socket_path: str,
    events: list[dict],
    started: threading.Event,
    captured_request: list[dict],
    confirmation: bytes,
):
    """Run a one-connection mock subscribe server on socket_path.

    Captures the client's subscribe request into ``captured_request`` so
    tests can assert on the wire format.
    """
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(1)
    started.set()
    try:
        srv.settimeout(5.0)
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        # Read the subscribe request (one newline-terminated JSON)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        line, _ = buf.split(b"\n", 1)
        try:
            captured_request.append(json.loads(line))
        except json.JSONDecodeError:
            captured_request.append({"_malformed": line.decode("utf-8", "replace")})
        # Send subscription confirmation
        conn.sendall(confirmation)
        # Send canned events
        for event in events:
            conn.sendall(json.dumps(event).encode("utf-8") + b"\n")
            time.sleep(0.01)  # small gap so the consumer's recv loop interleaves
        # Hold the connection open briefly, then close
        time.sleep(0.1)
    finally:
        try:
            conn.close()
        except OSError:
            pass
        srv.close()


@pytest.fixture
def socket_path():
    """Per-test temp Unix socket path."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "faramesh.sock")
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass


@pytest.fixture
def start_mock_server():
    """Factory that starts a mock subscribe server. Returns (thread, captured_request_list).

    Usage:
        thread, captured = start_mock_server(socket_path, events, confirmation=b'...')
    """

    def _factory(
        socket_path: str,
        events: list[dict],
        confirmation: bytes = b'{"subscribed": true}\n',
    ) -> tuple[threading.Thread, list[dict]]:
        started = threading.Event()
        captured_request: list[dict] = []
        thread = threading.Thread(
            target=_mock_subscribe_server,
            args=(socket_path, events, started, captured_request, confirmation),
            daemon=True,
        )
        thread.start()
        started.wait(timeout=2.0)
        return thread, captured_request

    return _factory
