"""
Faramesh Middleware for Deep Agents (LangGraph-based harness).

Implements the AgentMiddleware interface that Deep Agents exposes:
  - before_agent: set up session context
  - wrap_model_call: inject governance awareness into system prompt
  - after_tool_call: govern tool execution results, record DPR

Usage:
    from faramesh.middleware import FarameshMiddleware

    agent = create_deep_agent(
        model=init_chat_model("anthropic:claude-sonnet-4-5"),
        tools=[my_tools],
        middleware=[FarameshMiddleware(policy="payment.yaml")],
    )

Also works as a generic LangGraph/LangChain middleware adapter
for any framework that supports before/after hooks.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("faramesh.middleware")


@dataclass
class FarameshMiddleware:
    """Faramesh governance middleware for Deep Agents and LangGraph harnesses.

    Intercepts tool calls at the middleware layer, submitting each to the
    Faramesh daemon for governance evaluation before allowing execution.
    """

    policy: str = ""
    agent_id: str = ""
    socket_path: str = ""
    fail_open: bool = False
    _session_start: float = field(default_factory=time.time, init=False, repr=False)
    _tool_count: int = field(default=0, init=False, repr=False)
    _deny_count: int = field(default=0, init=False, repr=False)

    def __post_init__(self):
        if not self.agent_id:
            self.agent_id = os.environ.get("FARAMESH_AGENT_ID", "deep-agent")
        if not self.socket_path:
            self.socket_path = os.environ.get("FARAMESH_SOCKET", "/tmp/faramesh.sock")
        if self.policy:
            os.environ.setdefault("FARAMESH_POLICY_PATH", self.policy)

    def before_agent(self, state: dict[str, Any]) -> dict[str, Any]:
        """Called before agent starts reasoning. Sets up governance context."""
        state.setdefault("faramesh", {})
        state["faramesh"]["agent_id"] = self.agent_id
        state["faramesh"]["session_start"] = self._session_start
        state["faramesh"]["tool_count"] = self._tool_count
        logger.debug("faramesh: before_agent, session context set")
        return state

    def wrap_model_call(
        self,
        model_call: Callable,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """Wrap the LLM call to inject governance context into system prompt."""
        governance_context = (
            "\n[Faramesh Governance Active] All tool calls are subject to policy "
            "evaluation. Actions may be PERMIT, DENY, or DEFER (require human approval). "
            "Do not attempt to bypass tool governance."
        )

        for msg in messages:
            if msg.get("role") == "system":
                msg["content"] = msg.get("content", "") + governance_context
                break
        else:
            messages.insert(0, {"role": "system", "content": governance_context.strip()})

        return model_call(messages, **kwargs)

    def after_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_result: Any,
        state: dict[str, Any],
    ) -> Any:
        """Called after each tool call. Governs the action and records DPR."""
        self._tool_count += 1

        from faramesh.autopatch import _govern_call, _normalize_effect

        try:
            result = _govern_call(tool_name, tool_args)
        except RuntimeError as exc:
            self._deny_count += 1
            logger.warning("faramesh: tool %s denied: %s", tool_name, exc)
            if self.fail_open:
                return tool_result
            raise

        effect = _normalize_effect(result.get("effect", ""))

        if effect == "DENY":
            self._deny_count += 1
            reason = result.get("reason_code") or "POLICY_DENY"
            logger.warning("faramesh: DENY %s — %s", tool_name, reason)
            raise RuntimeError(f"Faramesh DENY: {reason} (tool={tool_name})")

        if effect == "DEFER":
            token = result.get("defer_token", "")
            logger.info("faramesh: DEFER %s — awaiting approval", tool_name)
            raise RuntimeError(
                f"Faramesh DEFER: approval required (token={token}, tool={tool_name})"
            )

        # PERMIT — scan output for prompt injection before returning.
        scanned = self._scan_output(tool_name, tool_result)
        return scanned

    def _scan_output(self, tool_name: str, output: Any) -> Any:
        """Post-condition scan on tool output for prompt injection detection."""
        if not isinstance(output, str):
            return output

        injection_patterns = [
            "ignore previous instructions",
            "disregard all prior",
            "you are now",
            "system prompt override",
            "new instructions:",
            "forget everything",
        ]

        lower = output.lower()
        for pattern in injection_patterns:
            if pattern in lower:
                logger.warning(
                    "faramesh: potential prompt injection in %s output: pattern=%s",
                    tool_name,
                    pattern,
                )
                return f"[FARAMESH: Output from {tool_name} was sanitized — potential injection detected]"

        return output

    def get_stats(self) -> dict[str, Any]:
        """Return middleware statistics."""
        return {
            "agent_id": self.agent_id,
            "session_duration_s": time.time() - self._session_start,
            "tool_calls": self._tool_count,
            "deny_count": self._deny_count,
            "deny_rate": self._deny_count / max(self._tool_count, 1),
        }
