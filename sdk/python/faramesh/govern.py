"""
govern() — the A1 SDK shim decorator.

Wraps any callable so that every invocation is governed by the Faramesh
pipeline before the underlying function executes. Zero infrastructure required
in development mode — the daemon is auto-started on the first call.

    from faramesh import govern

    governed_refund = govern(stripe_refund, policy='payment.yaml', agent_id='payment-bot')
    result = governed_refund(amount=100, currency='usd')
    # Raises DenyError if DENY, blocks on DEFER until approved/timeout.
"""

from __future__ import annotations

import functools
import json
import uuid
from typing import Any, Callable, TypeVar

from ._binary import ensure_daemon_running
from .client import FarameshClient
from .exceptions import DenyError, DeferredError

F = TypeVar("F", bound=Callable[..., Any])

# Global client — shared across all governed functions in this process.
_client: FarameshClient | None = None
_session_id: str = str(uuid.uuid4())


def _get_client(socket_path: str) -> FarameshClient:
    global _client
    if _client is None or _client.socket_path != socket_path:
        _client = FarameshClient(socket_path=socket_path)
    return _client


def govern(
    fn: F,
    *,
    policy: str = "policy.yaml",
    agent_id: str | None = None,
    tool_id: str | None = None,
    socket_path: str = "/tmp/faramesh.sock",
    auto_start: bool = True,
) -> F:
    """Wrap a function with Faramesh governance.

    Args:
        fn: The function to govern.
        policy: Path to the policy YAML file.
        agent_id: Agent identity. Defaults to the function's module + name.
        tool_id: Tool identifier used in the policy. Defaults to fn.__name__.
        socket_path: Daemon Unix socket path.
        auto_start: If True, auto-start the daemon on the first call (dev mode).

    Returns:
        A wrapped function with the same signature, docstring, and type hints
        as the original. Raises DenyError on DENY, DeferredError on DEFER
        timeout or denial.

    Signature preservation:
        - functools.wraps copies __name__, __doc__, __annotations__, __module__
        - __wrapped__ is set to the original function for introspection
        - Pydantic BaseModel parameters are passed through unchanged
        - LangChain @tool decorator metadata is preserved
    """
    if agent_id is None:
        agent_id = f"{fn.__module__}.{fn.__qualname__}"
    if tool_id is None:
        tool_id = fn.__name__

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Auto-start the daemon on first call in development mode.
        if auto_start:
            ensure_daemon_running(policy=policy, socket_path=socket_path)

        client = _get_client(socket_path)

        # Serialize call arguments for governance.
        # We capture kwargs; positional args are tagged as positional_0, etc.
        gov_args = _serialize_args(fn, args, kwargs)

        decision = client.govern(
            agent_id=agent_id,
            session_id=_session_id,
            tool_id=tool_id,
            args=gov_args,
        )

        effect = decision.get("effect", "DENY")

        if effect == "DENY":
            raise DenyError(
                tool_id=tool_id,
                rule_id=decision.get("rule_id") or None,
                reason_code=decision.get("reason_code", "DENY"),
                reason=decision.get("reason", "denied by policy"),
            )

        if effect == "DEFER":
            defer_token = decision.get("defer_token", "")
            reason = decision.get("reason", "action requires human approval")
            # Block waiting for resolution.
            status = client.wait_for_defer(
                agent_id=agent_id,
                defer_token=defer_token,
            )
            if status == "approved":
                # Approved — execute the underlying function.
                pass
            else:
                expired = status == "expired"
                raise DeferredError(
                    tool_id=tool_id,
                    defer_token=defer_token,
                    reason=reason,
                    expired=expired,
                )

        # PERMIT or SHADOW — execute the underlying function.
        return fn(*args, **kwargs)

    # Preserve LangChain @tool and similar decorator metadata.
    if hasattr(fn, "name"):
        wrapper.name = fn.name  # type: ignore[attr-defined]
    if hasattr(fn, "description"):
        wrapper.description = fn.description  # type: ignore[attr-defined]
    if hasattr(fn, "args_schema"):
        wrapper.args_schema = fn.args_schema  # type: ignore[attr-defined]

    wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
    return wrapper  # type: ignore[return-value]


def _serialize_args(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Convert positional and keyword arguments to a governance-safe dict.

    Pydantic models are serialized via .model_dump() if available.
    Other objects fall back to str() for structural signature purposes.
    """
    import inspect
    result: dict[str, Any] = {}

    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        for name, value in bound.arguments.items():
            result[name] = _safe_value(value)
    except (TypeError, ValueError):
        # Fall back to positional naming if binding fails.
        for i, a in enumerate(args):
            result[f"arg{i}"] = _safe_value(a)
        result.update({k: _safe_value(v) for k, v in kwargs.items()})

    return result


def _safe_value(v: Any) -> Any:
    """Convert a value to something JSON-serializable for governance."""
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [_safe_value(i) for i in v]
    if isinstance(v, dict):
        return {k: _safe_value(val) for k, val in v.items()}
    # Pydantic v2
    if hasattr(v, "model_dump"):
        return v.model_dump()
    # Pydantic v1
    if hasattr(v, "dict"):
        try:
            return v.dict()
        except Exception:
            pass
    try:
        return json.loads(json.dumps(v, default=str))
    except Exception:
        return str(v)
