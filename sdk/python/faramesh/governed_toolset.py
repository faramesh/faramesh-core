"""GovernedToolSet — wrap framework tools with daemon interception."""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, Iterable, List, Optional, Sequence, Union

from .exceptions import ToolDeniedException
from .transport import detect_transport, govern_via_transport

ToolLike = Union[Callable[..., Any], Any]


def _tool_name(tool: ToolLike) -> str:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
    if name:
        return str(name)
    return tool.__class__.__name__


def _parse_govern_result(result: dict[str, Any]) -> None:
    effect = str(result.get("effect", "")).upper()
    if effect in ("PERMIT", "ALLOW", "EXECUTE"):
        return
    if effect in ("DENY", "DEFER", "HALT", "BLOCK", "ABSTAIN", "PENDING"):
        raise ToolDeniedException.from_govern_result(result)
    raise ToolDeniedException(
        human_message=f"unknown governance effect: {effect!r}",
        code="GOVERNANCE_ERROR",
        effect=effect,
    )


def _govern_call(agent_id: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    transport = detect_transport()
    tool_id = tool_name if "/" in tool_name else f"{tool_name}/invoke"
    return govern_via_transport(transport, tool_id, args, agent_id=agent_id)


def _wrap_callable(agent_id: str, fn: Callable[..., Any], tool_name: str) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        payload = {"args": list(args), "kwargs": kwargs}
        _parse_govern_result(_govern_call(agent_id, tool_name, payload))
        return fn(*args, **kwargs)

    @functools.wraps(fn)
    async def awrapper(*args: Any, **kwargs: Any) -> Any:
        payload = {"args": list(args), "kwargs": kwargs}
        _parse_govern_result(_govern_call(agent_id, tool_name, payload))
        return await fn(*args, **kwargs)

    if functools.iscoroutinefunction(fn):
        return awrapper
    return wrapper


def _wrap_langchain_tool(agent_id: str, tool: Any) -> Any:
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        BaseTool = None  # type: ignore

    if BaseTool is not None and isinstance(tool, BaseTool):
        name = _tool_name(tool)
        original_run = getattr(tool, "_run", None)
        original_arun = getattr(tool, "_arun", None)

        if callable(original_run):

            def _run(*args: Any, **kwargs: Any) -> Any:
                _parse_govern_result(_govern_call(agent_id, name, dict(kwargs) if kwargs else {"args": list(args)}))
                return original_run(*args, **kwargs)

            object.__setattr__(tool, "_run", _run)

        if callable(original_arun):

            async def _arun(*args: Any, **kwargs: Any) -> Any:
                _parse_govern_result(_govern_call(agent_id, name, dict(kwargs) if kwargs else {"args": list(args)}))
                return await original_arun(*args, **kwargs)

            object.__setattr__(tool, "_arun", _arun)
        return tool

    if callable(tool):
        return _wrap_callable(agent_id, tool, _tool_name(tool))
    return tool


class GovernedToolSet(List[Any]):
    """List of tools that consult the Faramesh daemon before execution."""

    def __init__(
        self,
        tools: Iterable[ToolLike],
        *,
        agent_id: Optional[str] = None,
    ) -> None:
        resolved = (agent_id or os.environ.get("FARAMESH_AGENT_ID", "")).strip()
        if not resolved:
            raise ValueError("agent_id is required (pass agent_id= or set FARAMESH_AGENT_ID)")
        self.agent_id = resolved
        wrapped: List[Any] = []
        for tool in tools:
            if callable(tool) and not hasattr(tool, "invoke"):
                wrapped.append(_wrap_callable(resolved, tool, _tool_name(tool)))
            else:
                wrapped.append(_wrap_langchain_tool(resolved, tool))
        super().__init__(wrapped)
