"""Low-level JSON-over-Unix-socket client for the Faramesh daemon."""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from typing import Any

from .exceptions import DaemonError


DEFAULT_SOCKET = "/tmp/faramesh.sock"
POLL_INTERVAL = 2.0  # seconds between DEFER status polls
CONNECT_TIMEOUT = 5.0


class FarameshClient:
    """Thread-safe client for the Faramesh governance daemon.

    Connects to the daemon via a Unix domain socket and sends
    newline-delimited JSON messages. Each govern() call opens a
    short-lived connection to keep the protocol simple.

    Args:
        socket_path: Path to the Unix domain socket (default: /tmp/faramesh.sock).
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET):
        self.socket_path = socket_path
        self._lock = threading.Lock()

    def govern(
        self,
        agent_id: str,
        session_id: str,
        tool_id: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit a tool call for governance.

        Returns a dict with keys:
            effect: "PERMIT" | "DENY" | "DEFER" | "SHADOW"
            rule_id: str
            reason: str
            reason_code: str
            defer_token: str (set when effect == "DEFER")
            latency_ms: int
        """
        msg = {
            "type": "govern",
            "call_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "session_id": session_id,
            "tool_id": tool_id,
            "args": args,
        }
        return self._send(msg)

    def poll_defer(self, agent_id: str, defer_token: str) -> str:
        """Poll the status of a pending DEFER.

        Returns one of: "pending" | "approved" | "denied" | "expired" | "resolved"
        """
        msg = {
            "type": "poll_defer",
            "agent_id": agent_id,
            "defer_token": defer_token,
        }
        resp = self._send(msg)
        return resp.get("status", "resolved")

    def wait_for_defer(
        self,
        agent_id: str,
        defer_token: str,
        timeout: float = 300.0,
    ) -> str:
        """Block until a DEFER is resolved, denied, or expired.

        Returns the final status.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.poll_defer(agent_id, defer_token)
            if status != "pending":
                return status
            time.sleep(POLL_INTERVAL)
        return "expired"

    def _send(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Send a single message and return the response."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect(self.socket_path)
            payload = json.dumps(msg).encode() + b"\n"
            sock.sendall(payload)
            # Read until newline.
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            sock.close()
            return json.loads(buf.split(b"\n")[0])
        except FileNotFoundError:
            raise DaemonError(
                f"Daemon socket not found at {self.socket_path}. "
                "Is the daemon running? Run: faramesh serve --policy policy.yaml"
            )
        except ConnectionRefusedError:
            raise DaemonError(
                f"Connection refused at {self.socket_path}. "
                "Is the daemon running? Run: faramesh serve --policy policy.yaml"
            )
        except OSError as e:
            raise DaemonError(f"Socket error communicating with daemon: {e}") from e
