"""
Faramesh adapter for LlamaIndex.

Provides governed tool wrappers for LlamaIndex's FunctionTool and workflow
system. LlamaIndex tools inherit from BaseTool and implement call() / acall().

Usage:
    from llama_index.core.tools import FunctionTool
    from faramesh.adapters.llamaindex import governed_function_tool

    def search_docs(query: str) -> str:
        '''Search internal documentation.'''
        return do_search(query)

    tool = governed_function_tool(
        search_docs,
        name="search_docs",
        description="Search internal docs",
        policy_tool_id="docs/search",
    )

    # Use in any LlamaIndex agent or workflow:
    agent = ReActAgent.from_tools([tool], llm=llm)
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("faramesh.adapters.llamaindex")


def governed_function_tool(
    fn: Callable,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    policy_tool_id: Optional[str] = None,
    fail_open: bool = False,
    **kwargs: Any,
) -> Any:
    """Create a LlamaIndex FunctionTool with Faramesh governance.

    The returned tool behaves identically to a standard FunctionTool
    but submits each invocation to Faramesh for policy evaluation
    before executing the underlying function.

    Args:
        fn: The function to wrap.
        name: Tool name (defaults to fn.__name__).
        description: Tool description (defaults to fn.__doc__).
        policy_tool_id: Faramesh policy tool ID (defaults to name).
        fail_open: Allow execution when governance is unavailable.
        **kwargs: Additional args passed to FunctionTool constructor.
    """
    from llama_index.core.tools import FunctionTool

    tool_name = name or fn.__name__
    tool_id = policy_tool_id or tool_name

    @functools.wraps(fn)
    def governed_fn(*args, **kw):
        from faramesh.autopatch import _govern_call, _normalize_effect

        try:
            result = _govern_call(tool_id, dict(kw))
        except RuntimeError:
            if fail_open:
                logger.warning("faramesh: governance error on %s (fail-open)", tool_id)
                return fn(*args, **kw)
            raise

        effect = _normalize_effect(result.get("effect", ""))
        if effect == "DENY":
            reason = result.get("reason_code") or "POLICY_DENY"
            raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_id})")
        if effect == "DEFER":
            token = result.get("defer_token", "")
            raise RuntimeError(f"Faramesh DEFER: approval required (token={token}, tool={tool_id})")
        return fn(*args, **kw)

    return FunctionTool.from_defaults(
        fn=governed_fn,
        name=tool_name,
        description=description or fn.__doc__ or "",
        **kwargs,
    )


def govern_llamaindex_tools(tools: list[Any]) -> list[Any]:
    """Wrap a list of existing LlamaIndex tools with governance.

    Each tool's call() method is monkey-patched to submit to Faramesh
    before executing. Idempotent.

    Args:
        tools: List of LlamaIndex tool instances.

    Returns:
        The same list with governance wrappers applied.
    """
    from faramesh.autopatch import _wrap_method

    for tool in tools:
        tool_id_fn = lambda self, a, kw: getattr(
            self, "name",
            getattr(getattr(self, "metadata", None), "name", type(self).__name__)
        )
        _wrap_method(type(tool), "call", "llamaindex", tool_id_fn)

    return tools
