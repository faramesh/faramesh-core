# sdk/decorators.py
from __future__ import annotations
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union, Awaitable, TypeVar
import inspect

from .client import (
    ExecutionGovernorClient,
    GovernorError,
    PendingAction,
)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# single client per process
_client: Optional[ExecutionGovernorClient] = None


def get_client() -> ExecutionGovernorClient:
    """Get or create the default Execution Governor Client."""
    global _client
    if _client:
        return _client
    _client = ExecutionGovernorClient.from_env()
    return _client


def set_client(client: ExecutionGovernorClient) -> None:
    """Set the default client instance."""
    global _client
    _client = client


def is_async_function(func: Callable[..., Any]) -> bool:
    """Check if a function is async."""
    return inspect.iscoroutinefunction(func) or inspect.isasyncgenfunction(func)


def guarded_action(tool: str, operation: str, client: Optional[ExecutionGovernorClient] = None):
    """Wrap ANY Python function (sync or async) and send to governor first.

    This decorator intercepts function calls and submits them to the Faramesh
    governance server for policy evaluation before execution.

    Behavior:
      - denied → raise GovernorError
      - pending → return PendingAction (does NOT execute fn)
      - allow → execute fn + report result

    Args:
        tool: Tool name (e.g., "shell", "http", "database").
        operation: Operation name (e.g., "run", "get", "query").
        client: Optional client instance (uses default if not provided).

    Example:
        ```python
        @guarded_action(tool="shell", operation="run")
        def run_command(cmd: str) -> str:
            return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
        ```
    """

    def decorator(fn: Callable[..., Union[T, Awaitable[T]]]) -> Callable[..., Union[T, Awaitable[T], PendingAction]]:
        if is_async_function(fn):
            @wraps(fn)
            async def async_wrapper(*args, **kwargs):
                gov_client = client or get_client()
                context = kwargs.pop("_context", None) or {}
                params: Dict[str, Any] = {
                    "args": [repr(a) for a in args],
                    "kwargs": kwargs,
                }

                resp = gov_client.submit_action(
                    tool=tool,
                    operation=operation,
                    params=params,
                    context=context,
                )

                status = resp.get("status")
                decision = resp.get("decision")
                reason = resp.get("reason")
                action_id = resp.get("id")

                if status == "denied":
                    raise GovernorError(f"Denied: {reason}")

                if status == "pending_approval":
                    return PendingAction(
                        id=action_id,
                        status=status or "pending_approval",
                        decision=decision or "require_approval",
                        reason=reason,
                        approval_token=resp.get("approval_token"),
                        risk_level=resp.get("risk_level"),
                    )

                try:
                    result = await fn(*args, **kwargs)
                    gov_client.report_result(action_id, success=True)
                    return result
                except Exception as e:
                    gov_client.report_result(action_id, success=False, error=str(e))
                    raise

            return async_wrapper
        else:
            @wraps(fn)
            def sync_wrapper(*args, **kwargs):
                gov_client = client or get_client()
                context = kwargs.pop("_context", None) or {}
                params: Dict[str, Any] = {
                    "args": [repr(a) for a in args],
                    "kwargs": kwargs,
                }

                resp = gov_client.submit_action(
                    tool=tool,
                    operation=operation,
                    params=params,
                    context=context,
                )

                status = resp.get("status")
                decision = resp.get("decision")
                reason = resp.get("reason")
                action_id = resp.get("id")

                if status == "denied":
                    raise GovernorError(f"Denied: {reason}")

                if status == "pending_approval":
                    return PendingAction(
                        id=action_id,
                        status=status or "pending_approval",
                        decision=decision or "require_approval",
                        reason=reason,
                        approval_token=resp.get("approval_token"),
                        risk_level=resp.get("risk_level"),
                    )

                try:
                    result = fn(*args, **kwargs)
                    gov_client.report_result(action_id, success=True)
                    return result
                except Exception as e:
                    gov_client.report_result(action_id, success=False, error=str(e))
                    raise

            return sync_wrapper

    return decorator
