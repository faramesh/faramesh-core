"""
Faramesh adapter for Pydantic AI.

Provides a governed tool wrapper that integrates with Pydantic AI's
@agent.tool / @agent.tool_plain decorator system and RunContext.

Usage:
    from pydantic_ai import Agent
    from faramesh.adapters.pydantic_ai import governed_tool

    agent = Agent('openai:gpt-4o', deps_type=MyDeps)

    @governed_tool(agent, policy_tool_id="stripe/refund")
    async def refund_payment(ctx: RunContext[MyDeps], amount: float, reason: str) -> str:
        # This tool call is governed by Faramesh before execution.
        return await ctx.deps.stripe.refund(amount=amount, reason=reason)
"""
from __future__ import annotations

import functools
import logging
import os
from typing import Any, Callable, Optional

logger = logging.getLogger("faramesh.adapters.pydantic_ai")


def governed_tool(
    agent: Any,
    *,
    policy_tool_id: Optional[str] = None,
    retries: int = 1,
    plain: bool = False,
):
    """Decorator that registers a tool with both Pydantic AI and Faramesh governance.

    Args:
        agent: Pydantic AI Agent instance.
        policy_tool_id: Tool ID for Faramesh policy evaluation.
                        Defaults to the function name.
        retries: Number of retries for the tool (passed to Pydantic AI).
        plain: If True, uses @agent.tool_plain (no RunContext).
    """
    def decorator(fn: Callable) -> Callable:
        tool_id = policy_tool_id or fn.__name__

        @functools.wraps(fn)
        async def governed_wrapper(*args, **kwargs):
            from faramesh.autopatch import _govern_call, _normalize_effect

            call_args = dict(kwargs)
            if args and len(args) > 1:
                call_args["_positional"] = list(args[1:])

            result = _govern_call(tool_id, call_args)
            effect = _normalize_effect(result.get("effect", ""))

            if effect == "DENY":
                reason = result.get("reason_code") or "POLICY_DENY"
                raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_id})")
            if effect == "DEFER":
                token = result.get("defer_token", "")
                raise RuntimeError(f"Faramesh DEFER: approval required (token={token}, tool={tool_id})")

            return await fn(*args, **kwargs) if _is_async(fn) else fn(*args, **kwargs)

        if plain:
            agent.tool_plain(retries=retries)(governed_wrapper)
        else:
            agent.tool(retries=retries)(governed_wrapper)

        return governed_wrapper
    return decorator


def _is_async(fn: Callable) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)
