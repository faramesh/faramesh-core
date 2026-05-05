"""Lifecycle-callback subscription for the Faramesh daemon.

Wraps the daemon's ``callback_subscribe`` socket protocol so Python
consumers can react to events that follow a governance decision —
``defer_resolved`` (a deferred decision was approved or denied through
the SDK or CLI), ``defer_expired``, and similar post-decision callbacks.

Where :mod:`faramesh.audit` emits decisions at the moment they are
made, this stream emits what happens to them afterwards.

Each event includes ``event_type`` plus a payload appropriate to the
event. For ``defer_resolved`` that is at minimum ``defer_token``,
``status`` (``"approved"`` / ``"denied"`` / ``"expired"``), ``approved``
(bool), ``approver_id``, ``reason``, and ``timestamp``. ``defer_token``
links each resolution back to its originating DEFER record on the
decision stream.

Note: the daemon also mirrors every decision onto this stream as
``event_type == "decision"`` (in addition to broadcasting on
``audit_subscribe``). Consumers subscribing to both streams should
filter that mirror out to avoid double-handling.

Example:

    >>> from faramesh import callbacks
    >>>
    >>> def on_event(event: dict) -> None:
    ...     if event.get("event_type") == "defer_resolved":
    ...         print(event["defer_token"], event["status"])
    >>>
    >>> with callbacks.subscribe(on_event):
    ...     run_my_agent()

The callback runs on a background daemon thread. The daemon buffers ~64
events per subscriber and silently drops further events if the consumer
falls behind.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._subscription import CALLBACK_SUBSCRIBE, Subscription

__all__ = ["Subscription", "subscribe"]


def subscribe(
    callback: Callable[[dict[str, Any]], None],
    *,
    socket_path: str | None = None,
    connect_timeout: float = 5.0,
) -> Subscription:
    """Subscribe to the daemon's lifecycle stream (``callback_subscribe``).

    Emits events that follow a governance decision: ``defer_resolved``
    (a deferred decision was approved or denied), ``defer_expired``, and
    similar. Also mirrors every decision as ``event_type == "decision"``;
    consumers subscribing to both streams should filter that mirror out.

    Note: this stream does not support agent_id filtering. The daemon
    doesn't filter, and many lifecycle events (notably ``defer_resolved``
    from the ``agent approve`` CLI path) are sparse and don't include
    ``agent_id``, so any client-side filter would silently drop them.
    Filter inside your callback if needed.

    Args:
        callback: Invoked once per lifecycle event from a background thread.
        socket_path: Path to the daemon's Unix socket. Defaults to
            ``$FARAMESH_SOCKET`` then ``/tmp/faramesh.sock``.
        connect_timeout: Seconds to wait for connect and the
            subscription confirmation.

    Returns:
        A ``Subscription`` handle.

    Raises:
        ConnectionError: The socket could not be opened or the request
            could not be sent.
        TimeoutError: The daemon did not return the subscription
            confirmation within ``connect_timeout`` seconds.
    """
    sub = Subscription(
        callback,
        request_type=CALLBACK_SUBSCRIBE,
        socket_path=socket_path,
        connect_timeout=connect_timeout,
    )
    sub.start()
    return sub
