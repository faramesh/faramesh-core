"""
Faramesh LangChain/LangGraph drop-in interceptor.

This adapter installs explicit pre-execution governance for LangChain and LangGraph
agent tool calls without relying on global sitecustomize auto-loading.

Drop-in usage:
    from faramesh.adapters.langchain import install_langchain_interceptor

    install_langchain_interceptor(
        policy="policy.fpl",
        agent_id="support-agent",
        fail_open=False,
        include_langgraph=True,
    )

    # Build and run your agent as usual.
"""
from __future__ import annotations

import functools
import importlib
import inspect
import logging
import os
from contextvars import ContextVar
from typing import Any

logger = logging.getLogger("faramesh.adapters.langchain")

_GOVERNANCE_DEPTH: ContextVar[int] = ContextVar("faramesh_langchain_governance_depth", default=0)


def install_langchain_interceptor(
    *,
    policy: str | None = None,
    agent_id: str | None = None,
    fail_open: bool = False,
    include_langgraph: bool = True,
) -> dict[str, list[str]]:
    """Install LangChain/LangGraph interception hooks.

    This is idempotent for each patched method and safe to call multiple times.

    Args:
        policy: Optional policy file path to set as FARAMESH_POLICY_PATH.
        agent_id: Optional agent id to set as FARAMESH_AGENT_ID.
        fail_open: Permit execution if governance transport is unavailable.
        include_langgraph: Also patch LangGraph ToolNode dispatch internals.

    Returns:
        Dict describing which methods were patched.
    """
    if policy:
        os.environ.setdefault("FARAMESH_POLICY_PATH", policy)
    if agent_id:
        os.environ.setdefault("FARAMESH_AGENT_ID", agent_id)

    patched: dict[str, list[str]] = {"langchain": [], "langgraph": []}

    patched["langchain"] = _patch_langchain_basetool(fail_open=fail_open)
    if include_langgraph:
        patched["langgraph"] = _patch_langgraph_toolnode(fail_open=fail_open)

    return {k: v for k, v in patched.items() if v}


def install(**kwargs: Any) -> dict[str, list[str]]:
    """Alias for install_langchain_interceptor()."""
    return install_langchain_interceptor(**kwargs)


def _patch_langchain_basetool(*, fail_open: bool) -> list[str]:
    patched_methods: list[str] = []

    cls = None
    for module_path in ("langchain_core.tools", "langchain.tools"):
        try:
            module = importlib.import_module(module_path)
            cls = getattr(module, "BaseTool", None)
            if cls is not None:
                break
        except ImportError:
            continue

    if cls is None:
        return patched_methods

    for method_name in ("invoke", "ainvoke", "run", "arun"):
        if _wrap_tool_method(cls, method_name, fail_open=fail_open):
            patched_methods.append(method_name)

    return patched_methods


def _patch_langgraph_toolnode(*, fail_open: bool) -> list[str]:
    patched_methods: list[str] = []

    try:
        module = importlib.import_module("langgraph.prebuilt.tool_node")
    except ImportError:
        return patched_methods

    cls = getattr(module, "ToolNode", None)
    if cls is None:
        return patched_methods

    has_execute_sync = getattr(cls, "_execute_tool_sync", None) is not None
    has_execute_async = getattr(cls, "_execute_tool_async", None) is not None

    execute_sync_patched = False
    execute_async_patched = False
    if has_execute_sync:
        execute_sync_patched = _wrap_toolnode_execute_method(
            cls, "_execute_tool_sync", fail_open=fail_open
        )
    if has_execute_async:
        execute_async_patched = _wrap_toolnode_execute_method(
            cls, "_execute_tool_async", fail_open=fail_open
        )

    if execute_sync_patched:
        patched_methods.append("_execute_tool_sync")
    if execute_async_patched:
        patched_methods.append("_execute_tool_async")

    # Fallback for older ToolNode implementations.
    if not has_execute_sync and _wrap_toolnode_method(
        cls, "_run_one", fail_open=fail_open
    ):
        patched_methods.append("_run_one")
    if not has_execute_async and _wrap_toolnode_method(
        cls, "_arun_one", fail_open=fail_open
    ):
        patched_methods.append("_arun_one")

    return patched_methods


def _wrap_toolnode_execute_method(
    cls: type, method_name: str, *, fail_open: bool
) -> bool:
    original = getattr(cls, method_name, None)
    if original is None:
        return False
    if getattr(original, "_faramesh_langchain_patched", False):
        return False

    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_wrapper(self, *args: Any, **kwargs: Any) -> Any:
            request = _extract_tool_request_from_execute_args(args, kwargs)
            tool_call = _extract_tool_call_from_request(request)
            tool_name = str(tool_call.get("name", "unknown_tool"))
            payload = {
                "framework": "langgraph",
                "method": method_name,
                "tool_name": tool_name,
                "tool_call_id": tool_call.get("id") or tool_call.get("tool_call_id"),
                "input": _json_safe(tool_call.get("args", {})),
            }
            _enforce_policy(
                tool_id=f"{tool_name}/{method_name}",
                payload=payload,
                fail_open=fail_open,
            )

            token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
            try:
                return await original(self, *args, **kwargs)
            finally:
                _GOVERNANCE_DEPTH.reset(token)

        async_wrapper._faramesh_langchain_patched = True
        setattr(cls, method_name, async_wrapper)
        return True

    @functools.wraps(original)
    def sync_wrapper(self, *args: Any, **kwargs: Any) -> Any:
        request = _extract_tool_request_from_execute_args(args, kwargs)
        tool_call = _extract_tool_call_from_request(request)
        tool_name = str(tool_call.get("name", "unknown_tool"))
        payload = {
            "framework": "langgraph",
            "method": method_name,
            "tool_name": tool_name,
            "tool_call_id": tool_call.get("id") or tool_call.get("tool_call_id"),
            "input": _json_safe(tool_call.get("args", {})),
        }
        _enforce_policy(
            tool_id=f"{tool_name}/{method_name}",
            payload=payload,
            fail_open=fail_open,
        )

        token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
        try:
            return original(self, *args, **kwargs)
        finally:
            _GOVERNANCE_DEPTH.reset(token)

    sync_wrapper._faramesh_langchain_patched = True
    setattr(cls, method_name, sync_wrapper)
    return True


def _wrap_tool_method(cls: type, method_name: str, *, fail_open: bool) -> bool:
    original = getattr(cls, method_name, None)
    if original is None:
        return False
    if getattr(original, "_faramesh_langchain_patched", False):
        return False

    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_wrapper(self, *args: Any, **kwargs: Any) -> Any:
            if _GOVERNANCE_DEPTH.get() > 0:
                return await original(self, *args, **kwargs)

            tool_name = getattr(self, "name", type(self).__name__)
            tool_input = _extract_tool_input(method_name, args, kwargs)
            tool_call_id = _extract_tool_call_id(tool_input, kwargs)
            payload = _build_payload(
                framework="langchain",
                method=method_name,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_call_id=tool_call_id,
                kwargs=kwargs,
            )
            _enforce_policy(
                tool_id=f"{tool_name}/{method_name}",
                payload=payload,
                fail_open=fail_open,
            )

            token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
            try:
                return await original(self, *args, **kwargs)
            finally:
                _GOVERNANCE_DEPTH.reset(token)

        async_wrapper._faramesh_langchain_patched = True
        setattr(cls, method_name, async_wrapper)
        return True

    @functools.wraps(original)
    def sync_wrapper(self, *args: Any, **kwargs: Any) -> Any:
        if _GOVERNANCE_DEPTH.get() > 0:
            return original(self, *args, **kwargs)

        tool_name = getattr(self, "name", type(self).__name__)
        tool_input = _extract_tool_input(method_name, args, kwargs)
        tool_call_id = _extract_tool_call_id(tool_input, kwargs)
        payload = _build_payload(
            framework="langchain",
            method=method_name,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_call_id=tool_call_id,
            kwargs=kwargs,
        )
        _enforce_policy(
            tool_id=f"{tool_name}/{method_name}",
            payload=payload,
            fail_open=fail_open,
        )

        token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
        try:
            return original(self, *args, **kwargs)
        finally:
            _GOVERNANCE_DEPTH.reset(token)

    sync_wrapper._faramesh_langchain_patched = True
    setattr(cls, method_name, sync_wrapper)
    return True


def _wrap_toolnode_method(cls: type, method_name: str, *, fail_open: bool) -> bool:
    original = getattr(cls, method_name, None)
    if original is None:
        return False
    if getattr(original, "_faramesh_langchain_patched", False):
        return False

    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_wrapper(self, *args: Any, **kwargs: Any) -> Any:
            tool_call = _extract_tool_call_from_toolnode_args(args, kwargs)
            tool_name = str(tool_call.get("name", "unknown_tool"))
            payload = {
                "framework": "langgraph",
                "method": method_name,
                "tool_name": tool_name,
                "tool_call_id": tool_call.get("id") or tool_call.get("tool_call_id"),
                "input": _json_safe(tool_call.get("args", {})),
            }
            _enforce_policy(
                tool_id=f"{tool_name}/{method_name}",
                payload=payload,
                fail_open=fail_open,
            )

            token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
            try:
                return await original(self, *args, **kwargs)
            finally:
                _GOVERNANCE_DEPTH.reset(token)

        async_wrapper._faramesh_langchain_patched = True
        setattr(cls, method_name, async_wrapper)
        return True

    @functools.wraps(original)
    def sync_wrapper(self, *args: Any, **kwargs: Any) -> Any:
        tool_call = _extract_tool_call_from_toolnode_args(args, kwargs)
        tool_name = str(tool_call.get("name", "unknown_tool"))
        payload = {
            "framework": "langgraph",
            "method": method_name,
            "tool_name": tool_name,
            "tool_call_id": tool_call.get("id") or tool_call.get("tool_call_id"),
            "input": _json_safe(tool_call.get("args", {})),
        }
        _enforce_policy(
            tool_id=f"{tool_name}/{method_name}",
            payload=payload,
            fail_open=fail_open,
        )

        token = _GOVERNANCE_DEPTH.set(_GOVERNANCE_DEPTH.get() + 1)
        try:
            return original(self, *args, **kwargs)
        finally:
            _GOVERNANCE_DEPTH.reset(token)

    sync_wrapper._faramesh_langchain_patched = True
    setattr(cls, method_name, sync_wrapper)
    return True


def _extract_tool_request_from_execute_args(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any | None:
    if args:
        return args[0]
    return kwargs.get("request")


def _extract_tool_call_from_request(request: Any | None) -> dict[str, Any]:
    if request is None:
        return {}

    tool_call = getattr(request, "tool_call", None)
    if isinstance(tool_call, dict):
        return tool_call

    if isinstance(request, dict):
        maybe_call = request.get("tool_call")
        if isinstance(maybe_call, dict):
            return maybe_call

    return {}


def _extract_tool_input(method_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if method_name in ("run", "arun"):
        if args:
            return args[0]
        return kwargs.get("tool_input")
    if method_name in ("invoke", "ainvoke"):
        if args:
            return args[0]
        return kwargs.get("input")
    if args:
        return args[0]
    return kwargs


def _extract_tool_call_from_toolnode_args(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    if args and isinstance(args[0], dict):
        return args[0]
    call = kwargs.get("call")
    if isinstance(call, dict):
        return call
    return {}


def _extract_tool_call_id(tool_input: Any, kwargs: dict[str, Any]) -> str | None:
    if "tool_call_id" in kwargs and kwargs.get("tool_call_id") is not None:
        return str(kwargs.get("tool_call_id"))

    if isinstance(tool_input, dict):
        if tool_input.get("tool_call_id") is not None:
            return str(tool_input.get("tool_call_id"))
        if tool_input.get("id") is not None:
            return str(tool_input.get("id"))
    return None


def _build_payload(
    *,
    framework: str,
    method: str,
    tool_name: str,
    tool_input: Any,
    tool_call_id: str | None,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "framework": framework,
        "method": method,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "input": _json_safe(tool_input),
    }

    if "metadata" in kwargs:
        payload["metadata"] = _json_safe(kwargs.get("metadata"))
    if "tags" in kwargs:
        payload["tags"] = _json_safe(kwargs.get("tags"))
    if "run_name" in kwargs:
        payload["run_name"] = _json_safe(kwargs.get("run_name"))

    return payload


def _enforce_policy(*, tool_id: str, payload: dict[str, Any], fail_open: bool) -> None:
    from faramesh.autopatch import _govern_call, _normalize_effect, _require_defer_approval

    try:
        result = _govern_call(tool_id, payload)
    except Exception:
        if fail_open:
            logger.warning("faramesh: governance transport failed for %s (fail-open)", tool_id)
            return
        raise

    effect = _normalize_effect(result.get("effect", ""))
    if effect == "PERMIT":
        return

    if effect == "DENY":
        reason = result.get("reason_code") or "POLICY_DENY"
        raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_id})")

    if effect == "DEFER":
        try:
            _require_defer_approval(tool_id, result)
        except Exception:
            if fail_open:
                logger.warning("faramesh: defer approval wait failed for %s (fail-open)", tool_id)
                return
            raise



def _json_safe(value: Any) -> Any:
    from faramesh.autopatch import _json_safe as _autopatch_json_safe

    return _autopatch_json_safe(value)
