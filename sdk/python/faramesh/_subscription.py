"""Shared subscription machinery for Faramesh's SDK socket streams.

Internal module — consumers should use :mod:`faramesh.audit` (decision
stream) or :mod:`faramesh.callbacks` (lifecycle stream) rather than
importing from here directly.

Both public modules wrap the same Unix-socket protocol: send a
newline-delimited JSON request of a known ``type`` (``audit_subscribe``
or ``callback_subscribe``), wait for a ``{"subscribed": true, ...}``
confirmation, then read newline-delimited JSON events on a background
thread until the consumer closes the subscription.
"""

from __future__ import annotations

import json
import logging
import os
import socket as _socket
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("faramesh.subscription")

AUDIT_SUBSCRIBE = "audit_subscribe"
CALLBACK_SUBSCRIBE = "callback_subscribe"


def default_socket_path() -> str:
    """Resolve the daemon socket path. Matches autopatch.py's convention."""
    return os.environ.get("FARAMESH_SOCKET", "/tmp/faramesh.sock")


class Subscription:
    """Handle for an active subscription to one of the daemon's streams.

    Constructed via :func:`faramesh.audit.subscribe` (decisions) or
    :func:`faramesh.callbacks.subscribe` (lifecycle). Use as a context
    manager (preferred) or call ``close()`` explicitly.
    """

    def __init__(
        self,
        callback: Callable[[dict[str, Any]], None],
        *,
        request_type: str,
        agent_id: str | None = None,
        socket_path: str | None = None,
        connect_timeout: float = 5.0,
    ):
        self._callback = callback
        self._request_type = request_type
        self._agent_id = agent_id
        self._socket_path = socket_path or default_socket_path()
        self._connect_timeout = connect_timeout

        self._sock: _socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._start_error: Exception | None = None

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def start(self) -> None:
        """Open the socket, send the subscribe request, and start the read loop.

        Blocks until the daemon's ``{"subscribed": true}`` confirmation arrives
        (or the connect/handshake fails), so that errors surface immediately
        rather than from the background thread.
        """
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            sock.settimeout(self._connect_timeout)
            sock.connect(self._socket_path)
        except OSError as exc:
            sock.close()
            raise ConnectionError(
                f"Failed to connect to Faramesh daemon at {self._socket_path}: {exc}"
            ) from exc

        # The daemon's callback_subscribe handler ignores agent_id, so we omit
        # the field on that stream rather than sending an empty value.
        payload: dict[str, Any] = {"type": self._request_type}
        if self._request_type == AUDIT_SUBSCRIBE:
            payload["agent_id"] = self._agent_id or ""
        request = json.dumps(payload).encode("utf-8") + b"\n"
        try:
            sock.sendall(request)
        except OSError as exc:
            sock.close()
            raise ConnectionError(
                f"Failed to send {self._request_type} request: {exc}"
            ) from exc

        sock.settimeout(None)  # blocking mode for the long-lived stream
        self._sock = sock
        self._thread = threading.Thread(
            target=self._run,
            name=f"faramesh-{self._request_type.replace('_', '-')}",
            daemon=True,
        )
        self._thread.start()

        # Wait for the subscription confirmation (or an error from _run)
        if not self._ready.wait(timeout=self._connect_timeout):
            self.close()
            raise TimeoutError(
                "Did not receive subscription confirmation from Faramesh daemon"
            )
        if self._start_error is not None:
            err = self._start_error
            self.close()
            raise err

    def close(self) -> None:
        """Stop the read loop and close the socket. Safe to call multiple times."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.shutdown(_socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    def _run(self) -> None:
        """Background thread: read newline-delimited JSON events, invoke callback."""
        assert self._sock is not None
        sock = self._sock
        buf = b""
        confirmed = False

        try:
            while not self._stop.is_set():
                try:
                    chunk = sock.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.warning("Skipping malformed event: %s", exc)
                        continue

                    if not confirmed:
                        confirmed = True
                        if event.get("subscribed") is True:
                            self._ready.set()
                            continue
                        self._start_error = RuntimeError(
                            f"Unexpected handshake response: {event}"
                        )
                        self._ready.set()
                        return

                    # Client-side agent_id filter (daemon does not filter)
                    if self._agent_id and event.get("agent_id") != self._agent_id:
                        continue

                    try:
                        self._callback(event)
                    except Exception:
                        logger.exception(
                            "Subscription callback raised; stream continuing"
                        )
        finally:
            # Unblock start() if we exited before confirmation
            if not self._ready.is_set():
                if self._start_error is None:
                    self._start_error = ConnectionError(
                        "Subscription stream ended before confirmation"
                    )
                self._ready.set()
