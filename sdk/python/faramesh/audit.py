"""Decision-stream subscription for the Faramesh daemon.

Wraps the daemon's ``audit_subscribe`` socket protocol so Python
consumers can react to every governance decision in real time. Same
protocol as ``faramesh audit tail``.

Each event is a governance **decision** (PERMIT / DENY / DEFER) at the
moment it is made. To capture lifecycle events that follow a
decision — the eventual approval or denial of a DEFER, expirations,
and similar — also subscribe via :mod:`faramesh.callbacks`.

Example:

    >>> from faramesh import audit
    >>>
    >>> with audit.subscribe(lambda e: print(e["effect"], e["tool_id"])):
    ...     run_my_agent()

The callback runs on a background daemon thread. The daemon buffers ~64
events per subscriber and silently drops further events if the consumer
falls behind, so keep the callback fast — for slow downstream work
(network calls, etc.), enqueue events and process them out-of-band.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._subscription import AUDIT_SUBSCRIBE, Subscription

__all__ = ["Subscription", "subscribe"]


def subscribe(
    callback: Callable[[dict[str, Any]], None],
    *,
    agent_id: str | None = None,
    socket_path: str | None = None,
    connect_timeout: float = 5.0,
) -> Subscription:
    """Subscribe to the daemon's decision stream (``audit_subscribe``).

    Each event is a dict with fields including ``effect``, ``agent_id``,
    ``tool_id``, ``operation``, ``rule_id``, ``reason_code``, ``record_id``
    (DPR record id), ``defer_token``, ``latency_ms``, ``timestamp``,
    ``policy_version``, ``incident_category``, ``incident_severity``,
    ``args``, and others.

    Args:
        callback: Invoked once per decision event from a background thread.
        agent_id: Optional client-side filter. The daemon does not filter
            by agent_id; the wrapper drops events whose ``agent_id`` field
            does not match.
        socket_path: Path to the daemon's Unix socket. Defaults to
            ``$FARAMESH_SOCKET`` then ``/tmp/faramesh.sock``.
        connect_timeout: Seconds to wait for connect and the
            subscription confirmation.

    Returns:
        A ``Subscription`` handle. Use as a context manager or call
        ``.close()`` to stop.

    Raises:
        ConnectionError: The socket could not be opened or the request
            could not be sent.
        TimeoutError: The daemon did not return the subscription
            confirmation within ``connect_timeout`` seconds.
    """
    sub = Subscription(
        callback,
        request_type=AUDIT_SUBSCRIBE,
        agent_id=agent_id,
        socket_path=socket_path,
        connect_timeout=connect_timeout,
    )
    sub.start()
    return sub
