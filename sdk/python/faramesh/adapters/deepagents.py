"""Faramesh DeepAgents drop-in interceptor.

This adapter provides a first-class integration path for LangChain DeepAgents.
It installs LangChain/LangGraph execution-layer interception and patches the
DeepAgents `create_deep_agent` entrypoint so graphs assembled after
installation still inherit Faramesh governance hooks.
"""
from __future__ import annotations

import functools
import importlib
import logging
import os
from typing import Any

from .langchain import install_langchain_interceptor

logger = logging.getLogger("faramesh.adapters.deepagents")

_DEEPAGENTS_FAIL_OPEN = False
_DEEPAGENTS_INCLUDE_LANGGRAPH = True


def install_deepagents_interceptor(
    *,
    policy: str | None = None,
    agent_id: str | None = None,
    fail_open: bool = False,
    include_langgraph: bool = True,
) -> dict[str, list[str]]:
    """Install DeepAgents interception hooks.

    This adapter keeps DeepAgents governance aligned with the existing
    LangChain/LangGraph interception path while adding DeepAgents-specific
    entrypoint coverage.

    Args:
        policy: Optional policy file path to set as FARAMESH_POLICY_PATH.
        agent_id: Optional agent id to set as FARAMESH_AGENT_ID.
        fail_open: Permit execution if governance transport is unavailable.
        include_langgraph: Also patch LangGraph ToolNode dispatch internals.

    Returns:
        Dict describing which methods/entrypoints were patched.
    """
    global _DEEPAGENTS_FAIL_OPEN, _DEEPAGENTS_INCLUDE_LANGGRAPH

    if policy:
        os.environ.setdefault("FARAMESH_POLICY_PATH", policy)
    if agent_id:
        os.environ.setdefault("FARAMESH_AGENT_ID", agent_id)

    _DEEPAGENTS_FAIL_OPEN = fail_open
    _DEEPAGENTS_INCLUDE_LANGGRAPH = include_langgraph

    patched: dict[str, list[str]] = {
        "langchain": [],
        "langgraph": [],
        "deepagents": [],
    }

    base = install_langchain_interceptor(
        fail_open=fail_open,
        include_langgraph=include_langgraph,
    )
    patched["langchain"] = base.get("langchain", [])
    patched["langgraph"] = base.get("langgraph", [])

    if _patch_deepagents_create_agent_entrypoint():
        patched["deepagents"].append("create_deep_agent")

    return {k: v for k, v in patched.items() if v}


def install(**kwargs: Any) -> dict[str, list[str]]:
    """Alias for install_deepagents_interceptor()."""
    return install_deepagents_interceptor(**kwargs)


def _patch_deepagents_create_agent_entrypoint() -> bool:
    """Patch DeepAgents graph assembly entrypoint.

    Wrapping `deepagents.graph.create_deep_agent` ensures LangChain/LangGraph
    interception is active at graph build time, including late import paths.
    """
    try:
        graph_mod = importlib.import_module("deepagents.graph")
    except Exception:
        return False

    original = getattr(graph_mod, "create_deep_agent", None)
    if original is None:
        return False
    if getattr(original, "_faramesh_deepagents_patched", False):
        return False

    @functools.wraps(original)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        install_langchain_interceptor(
            fail_open=_DEEPAGENTS_FAIL_OPEN,
            include_langgraph=_DEEPAGENTS_INCLUDE_LANGGRAPH,
        )
        return original(*args, **kwargs)

    wrapper._faramesh_deepagents_patched = True
    setattr(graph_mod, "create_deep_agent", wrapper)

    # Mirror the patch on top-level re-export when present.
    try:
        top_mod = importlib.import_module("deepagents")
        top_create = getattr(top_mod, "create_deep_agent", None)
        if top_create is original:
            setattr(top_mod, "create_deep_agent", wrapper)
    except Exception:
        logger.debug("faramesh: deepagents top-level re-export patch skipped")

    return True
