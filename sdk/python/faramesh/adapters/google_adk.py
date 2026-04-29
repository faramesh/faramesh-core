"""
Faramesh adapter for Google Agent Development Kit (ADK).

Provides a governed tool wrapper that integrates with ADK's FunctionTool
and Agent system. ADK auto-wraps plain functions as FunctionTool when
placed in an Agent's tools list — this adapter governs before that
dispatch reaches the function body.

Usage:
    from google.adk.agents import Agent
    from faramesh.adapters.google_adk import faramesh_tool

    @faramesh_tool(policy_tool_id="weather/get")
    def get_weather(city: str, unit: str = "Celsius") -> dict:
        '''Retrieves the current weather for a city.'''
        return {"city": city, "temp": 22, "unit": unit}

    agent = Agent(
        name="weather_agent",
        model="gemini-2.0-flash",
        tools=[get_weather],   # governed via Faramesh
    )
"""
from __future__ import annotations

import functools
import logging
import os
from typing import Any, Callable, Optional

logger = logging.getLogger("faramesh.adapters.google_adk")


def faramesh_tool(
    *,
    policy_tool_id: Optional[str] = None,
    fail_open: bool = False,
):
    """Decorator that wraps an ADK function tool with Faramesh governance.

    ADK auto-converts decorated functions to FunctionTool via introspection.
    This wrapper preserves the function signature (name, docstring, type hints)
    so ADK's schema generation works correctly, while injecting governance
    before the function body executes.

    Args:
        policy_tool_id: Tool ID for Faramesh policy. Defaults to function name.
        fail_open: If True, allow execution when governance is unavailable.
    """
    def decorator(fn: Callable) -> Callable:
        tool_id = policy_tool_id or fn.__name__

        @functools.wraps(fn)
        def governed_wrapper(*args, **kwargs):
            from faramesh.autopatch import _govern_call, _normalize_effect

            try:
                result = _govern_call(tool_id, dict(kwargs))
            except RuntimeError:
                if fail_open:
                    logger.warning("faramesh: governance error on %s (fail-open)", tool_id)
                    return fn(*args, **kwargs)
                raise

            effect = _normalize_effect(result.get("effect", ""))
            if effect == "DENY":
                reason = result.get("reason_code") or "POLICY_DENY"
                raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_id})")
            if effect == "DEFER":
                token = result.get("defer_token", "")
                raise RuntimeError(f"Faramesh DEFER: approval required (token={token}, tool={tool_id})")

            return fn(*args, **kwargs)

        return governed_wrapper
    return decorator


def govern_adk_agent(agent: Any) -> Any:
    """Wrap all tools in an existing ADK Agent with Faramesh governance.

    This modifies the agent's tools list in-place, wrapping each
    FunctionTool's underlying callable.

    Args:
        agent: google.adk.agents.Agent instance.

    Returns:
        The same agent instance (for chaining).
    """
    tools = getattr(agent, "tools", None) or []
    governed_tools = []

    for tool in tools:
        if callable(tool) and not getattr(tool, "_faramesh_governed", False):
            wrapped = faramesh_tool(policy_tool_id=getattr(tool, "__name__", str(tool)))(tool)
            wrapped._faramesh_governed = True
            governed_tools.append(wrapped)
        else:
            governed_tools.append(tool)

    if hasattr(agent, "tools"):
        agent.tools = governed_tools
    return agent
