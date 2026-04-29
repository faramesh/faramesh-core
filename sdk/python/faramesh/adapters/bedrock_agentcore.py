"""
Faramesh adapter for AWS Bedrock AgentCore.

Bedrock AgentCore is a managed platform — the agent runs in AWS infrastructure.
OS-level enforcement (seccomp, Landlock, netns) is not available. The enforcement
floor is the credential broker + Faramesh policy engine via SDK shim.

AgentCore supports multiple agent frameworks (Strands, LangGraph, CrewAI).
This adapter provides:
  1. An app-level middleware hook for bedrock-agentcore-sdk-python
  2. A Strands Agents hook integration
  3. SDK-level govern() wrapper for direct use in @app.entrypoint

Usage with bedrock-agentcore-sdk-python:

    from bedrock_agentcore.runtime import BedrockAgentCoreApp
    from faramesh.adapters.bedrock_agentcore import faramesh_middleware

    app = BedrockAgentCoreApp()
    faramesh_middleware(app)  # installs governance hooks

    @app.entrypoint
    async def my_agent(request, response_stream):
        # All tool calls governed via Faramesh
        ...

Usage with Strands Agents on AgentCore:

    from strands import Agent
    from faramesh.adapters.bedrock_agentcore import FarameshStrandsHook

    agent = Agent(
        model=model,
        tools=[my_tools],
        hooks=[FarameshStrandsHook(policy="payment.yaml")],
    )
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("faramesh.adapters.bedrock_agentcore")


def faramesh_middleware(app: Any) -> None:
    """Install Faramesh governance hooks on a BedrockAgentCoreApp.

    Wraps the @app.entrypoint handler so every agent invocation
    has governance context set up before execution begins.

    Args:
        app: BedrockAgentCoreApp instance.
    """
    orig_entrypoint = getattr(app, "entrypoint", None)
    if orig_entrypoint is None:
        logger.warning("faramesh: BedrockAgentCoreApp.entrypoint not found")
        return

    def governed_entrypoint(fn: Callable) -> Callable:
        import functools

        @functools.wraps(fn)
        async def wrapper(request: Any, response_stream: Any, *args, **kwargs):
            os.environ.setdefault("FARAMESH_AUTOLOAD", "1")
            os.environ.setdefault("FARAMESH_RUNTIME_KIND", "bedrock-agentcore")

            from faramesh.autopatch import install
            install()

            return await fn(request, response_stream, *args, **kwargs)

        return orig_entrypoint(wrapper)

    app.entrypoint = governed_entrypoint


@dataclass
class FarameshStrandsHook:
    """Strands Agents hook that governs tool invocations via Faramesh.

    Implements the Strands hook event interface:
      - agent_initialized: set up governance context
      - before_invocation: log session start
      - after_invocation: log session stats

    Tool-level governance is handled by the auto-patcher which intercepts
    at the Strands tool dispatch layer.
    """

    policy: str = ""
    agent_id: str = ""
    _tool_count: int = field(default=0, init=False, repr=False)
    _session_start: float = field(default_factory=time.time, init=False, repr=False)

    def __post_init__(self):
        if not self.agent_id:
            self.agent_id = os.environ.get("FARAMESH_AGENT_ID", "strands-agent")
        if self.policy:
            os.environ.setdefault("FARAMESH_POLICY_PATH", self.policy)

    def agent_initialized(self, **kwargs: Any) -> None:
        """Called when the Strands agent finishes initialization."""
        os.environ.setdefault("FARAMESH_AUTOLOAD", "1")
        from faramesh.autopatch import install
        patched = install()
        if patched:
            logger.info("faramesh: Strands agent initialized, patched: %s", patched)

    def before_invocation(self, **kwargs: Any) -> None:
        """Called before agent request processing begins."""
        self._session_start = time.time()
        logger.debug("faramesh: before_invocation for %s", self.agent_id)

    def after_invocation(self, **kwargs: Any) -> None:
        """Called after agent request completion."""
        duration = time.time() - self._session_start
        logger.debug("faramesh: after_invocation for %s (%.2fs)", self.agent_id, duration)

    def message_added(self, **kwargs: Any) -> None:
        """Called when messages are added to the conversation."""
        pass


def govern_agentcore_tool(
    fn: Callable,
    *,
    policy_tool_id: Optional[str] = None,
) -> Callable:
    """Wrap a function intended for Bedrock AgentCore with Faramesh governance.

    Use this for tools that will be invoked via AgentCore's tool execution
    pathway (via Strands, LangGraph, or direct).

    Args:
        fn: The tool function.
        policy_tool_id: Faramesh policy tool ID (defaults to fn.__name__).
    """
    import functools
    tool_id = policy_tool_id or fn.__name__

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from faramesh.autopatch import _govern_call, _normalize_effect

        result = _govern_call(tool_id, dict(kwargs))
        effect = _normalize_effect(result.get("effect", ""))
        if effect == "DENY":
            reason = result.get("reason_code") or "POLICY_DENY"
            raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_id})")
        if effect == "DEFER":
            token = result.get("defer_token", "")
            raise RuntimeError(f"Faramesh DEFER: approval required (token={token}, tool={tool_id})")
        return fn(*args, **kwargs)

    return wrapper
