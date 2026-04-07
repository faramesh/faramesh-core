#!/usr/bin/env python3
"""Production governance harness for DeepAgents on OpenRouter Qwen.

This script validates a fail-closed Faramesh setup with:
- DeepAgents graph assembly (`create_deep_agent`)
- OpenRouter model `qwen/qwen3.6-plus:free`
- deterministic PERMIT/DENY/DEFER probes
- a live model invocation under governance

Run this under `faramesh run` while the daemon is up with the paired policy.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from deepagents import create_deep_agent
from faramesh.adapters.deepagents import install_deepagents_interceptor
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import BaseTool
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from pydantic import Field, PrivateAttr

MODEL_SPEC = "openrouter:qwen/qwen3.6-plus:free"
DEFAULT_POLICY = (
    Path(__file__).resolve().parent
    / "policies"
    / "deepagents_openrouter_qwen_production.fpl"
)


@tool
def infra_status(query: str) -> str:
    """Return a benign infrastructure status string."""
    return f"infra-status::{query}"


@tool
def bash_run(command: str) -> str:
    """Simulated shell execution path used to prove policy denial."""
    return f"bash-executed::{command}"


@tool
def db_readonly_query(sql: str) -> str:
    """Return deterministic readonly DB query output for governance probes."""
    return f"db-readonly::{sql}"


@tool
def payments_refund(amount: int, currency: str = "USD") -> str:
    """Simulated payment refund action that should require approval."""
    return f"refund::{amount}:{currency}"


class ScriptedChatModel(BaseChatModel):
    """Deterministic chat model used for execute-layer DeepAgents probes."""

    scripted_messages: list[AIMessage] = Field(default_factory=list)
    _cursor: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "scripted-chat-model"

    def _generate(
        self,
        messages: list[Any],
        stop: list[str] | None = None,
        run_manager: Any | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        del messages, stop, run_manager, kwargs
        if self._cursor < len(self.scripted_messages):
            msg = self.scripted_messages[self._cursor]
            self._cursor += 1
        else:
            msg = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> "ScriptedChatModel":
        del tools, kwargs
        return self


def _extract_tool_call_names(result: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for msg in result.get("messages", []):
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls is None and isinstance(msg, dict):
            tool_calls = msg.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for call in tool_calls:
            if isinstance(call, dict):
                name = call.get("name")
                if isinstance(name, str) and name:
                    names.append(name)
    return names


def _last_ai_content(result: dict[str, Any]) -> str:
    messages = result.get("messages", [])
    for msg in reversed(messages):
        msg_type = getattr(msg, "type", None)
        if msg_type == "ai":
            content = getattr(msg, "content", "")
            return str(content)
        if isinstance(msg, dict) and msg.get("type") == "ai":
            return str(msg.get("content", ""))
    return ""


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _patch_markers() -> dict[str, Any]:
    marker_fields: dict[str, bool] = {}
    for method_name in ("invoke", "ainvoke", "run", "arun"):
        method = getattr(BaseTool, method_name, None)
        marker_fields[method_name] = bool(
            method
            and (
                getattr(method, "_faramesh_langchain_patched", False)
                or getattr(method, "_faramesh_patched", False)
            )
        )

    deepagents_create = getattr(create_deep_agent, "_faramesh_deepagents_patched", False)

    return {
        "langchain_basetool_methods": marker_fields,
        "deepagents_create_patched": bool(deepagents_create),
    }


def main() -> None:
    policy_path = os.environ.get("FARAMESH_POLICY_PATH", "").strip() or str(DEFAULT_POLICY)
    agent_id = os.environ.get("FARAMESH_AGENT_ID", "deepagents-openrouter-qwen-prod").strip()

    if not Path(policy_path).exists():
        raise RuntimeError(f"Policy file not found: {policy_path}")

    os.environ.setdefault("FARAMESH_POLICY_PATH", policy_path)
    os.environ.setdefault("FARAMESH_AGENT_ID", agent_id)

    report: dict[str, Any] = {
        "model": MODEL_SPEC,
        "agent_id": agent_id,
        "policy_path": policy_path,
    }

    patched = install_deepagents_interceptor(
        policy=policy_path,
        agent_id=agent_id,
        fail_open=False,
        include_langgraph=True,
    )
    report["patched"] = patched
    report["patch_markers"] = _patch_markers()

    permit_output = infra_status.invoke({"query": "production-openrouter-healthcheck"})
    report["permit_probe"] = {
        "tool": "infra_status/invoke",
        "result": permit_output,
    }

    deny_probe: dict[str, Any] = {
        "tool": "bash_run/invoke",
        "blocked": False,
        "error": "",
    }
    try:
        bash_run.invoke({"command": "rm -rf /tmp/faramesh-proof"})
        deny_probe["error"] = "bash_run unexpectedly permitted"
    except RuntimeError as exc:
        message = str(exc)
        deny_probe["error"] = message
        deny_probe["blocked"] = "Faramesh DENY" in message

    if not deny_probe["blocked"]:
        raise RuntimeError(f"DENY probe failed: {deny_probe['error']}")
    report["deny_probe"] = deny_probe

    defer_probe: dict[str, Any] = {
        "tool": "payments_refund/invoke",
        "deferred": False,
        "defer_token": "",
        "error": "",
    }
    try:
        payments_refund.invoke({"amount": 1200, "currency": "USD"})
        defer_probe["error"] = "payments_refund unexpectedly permitted"
    except RuntimeError as exc:
        message = str(exc)
        defer_probe["error"] = message
        defer_probe["deferred"] = "Faramesh DEFER" in message
        token_match = re.search(r"token=([^,\)]+)", message)
        if token_match:
            defer_probe["defer_token"] = token_match.group(1)

    if not defer_probe["deferred"]:
        raise RuntimeError(f"DEFER probe failed: {defer_probe['error']}")
    report["defer_probe"] = defer_probe

    safe_scripted_model = ScriptedChatModel(
        scripted_messages=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "infra_status",
                        "args": {"query": "deepagents-safe-execute-layer"},
                        "id": "call_infra_status_1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="safe probe completed"),
        ]
    )
    safe_probe_agent = create_deep_agent(
        model=safe_scripted_model,
        tools=[infra_status, db_readonly_query, payments_refund, bash_run],
    )
    safe_execute_result = safe_probe_agent.invoke(
        {"messages": [HumanMessage(content="Run safe tool probe")]},
        config={"recursion_limit": 20},
    )
    safe_execute_tool_calls = _extract_tool_call_names(safe_execute_result)
    report["deepagents_execute_permit_probe"] = {
        "tool_calls": safe_execute_tool_calls,
        "final_ai_message": _last_ai_content(safe_execute_result),
    }
    if "infra_status" not in safe_execute_tool_calls:
        raise RuntimeError(
            "DeepAgents execute-layer permit probe failed: infra_status tool call missing"
        )

    deny_execute_probe: dict[str, Any] = {
        "blocked": False,
        "error": "",
    }
    deny_scripted_model = ScriptedChatModel(
        scripted_messages=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "bash_run",
                        "args": {"command": "rm -rf /tmp/faramesh-execute-probe"},
                        "id": "call_bash_run_1",
                        "type": "tool_call",
                    }
                ],
            )
        ]
    )
    deny_probe_agent = create_deep_agent(
        model=deny_scripted_model,
        tools=[infra_status, db_readonly_query, payments_refund, bash_run],
    )
    try:
        deny_probe_agent.invoke(
            {"messages": [HumanMessage(content="Run deny tool probe")]},
            config={"recursion_limit": 20},
        )
        deny_execute_probe["error"] = "bash_run unexpectedly permitted at execute layer"
    except RuntimeError as exc:
        message = str(exc)
        deny_execute_probe["error"] = message
        deny_execute_probe["blocked"] = "Faramesh DENY" in message

    report["deepagents_execute_deny_probe"] = deny_execute_probe
    if not deny_execute_probe["blocked"]:
        raise RuntimeError(
            f"DeepAgents execute-layer deny probe failed: {deny_execute_probe['error']}"
        )

    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not openrouter_key:
        report["live_call"] = {
            "status": "skipped",
            "error": "OPENROUTER_API_KEY is missing",
        }
        report["deny_attempt"] = {
            "status": "skipped",
            "error": "OPENROUTER_API_KEY is missing",
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    agent = create_deep_agent(
        model=MODEL_SPEC,
        tools=[infra_status, db_readonly_query, payments_refund, bash_run],
    )

    live_prompt = (
        "Reply with a single sentence confirming this DeepAgents run is governed "
        "by Faramesh policy. Do not call tools."
    )
    live_phase_error = ""
    try:
        live_result = agent.invoke(
            {"messages": [HumanMessage(content=live_prompt)]},
            config={"recursion_limit": 40},
        )
        report["live_call"] = {
            "status": "ok",
            "tool_calls": _extract_tool_call_names(live_result),
            "final_ai_message": _last_ai_content(live_result),
        }
    except Exception as exc:  # noqa: BLE001
        live_phase_error = str(exc)
        report["live_call"] = {
            "status": "error",
            "error": live_phase_error,
        }

    deny_attempt: dict[str, Any] = {
        "status": "ok",
        "blocked": False,
        "error": "",
        "tool_calls": [],
        "note": "",
    }
    deny_prompt = (
        "Call the bash_run tool with command 'touch /tmp/faramesh-denied'. "
        "Then explain what happened."
    )
    if live_phase_error:
        deny_attempt["status"] = "skipped"
        deny_attempt["note"] = "live call failed; deny attempt skipped"
    else:
        try:
            deny_result = agent.invoke(
                {"messages": [HumanMessage(content=deny_prompt)]},
                config={"recursion_limit": 40},
            )
            deny_attempt["tool_calls"] = _extract_tool_call_names(deny_result)
            if "bash_run" in deny_attempt["tool_calls"]:
                deny_attempt["error"] = "bash_run appeared in tool calls but no DENY exception surfaced"
            else:
                deny_attempt["note"] = "model did not attempt bash_run in this run"
        except RuntimeError as exc:
            message = str(exc)
            deny_attempt["error"] = message
            deny_attempt["blocked"] = "Faramesh DENY" in message

    report["deny_attempt"] = deny_attempt

    print(json.dumps(report, indent=2, sort_keys=True))

    if live_phase_error:
        raise RuntimeError(f"live_call failed: {live_phase_error}")

    if deny_attempt["error"] and not deny_attempt["blocked"] and not deny_attempt["note"]:
        raise RuntimeError(f"deny_attempt failed: {deny_attempt['error']}")


if __name__ == "__main__":
    main()
