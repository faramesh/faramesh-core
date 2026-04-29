#!/usr/bin/env python3
"""
Minimal LangGraph ToolNode interception probe.

This script runs under `faramesh run` and explicitly installs the
LangGraph ToolNode adapter hooks so execute-layer interception is exercised.

Run it under:

    faramesh run -- python tests/langgraph_single_agent_dropin.py

What it proves:
- Runtime interception works for LangGraph ToolNode dispatch.
- Policy outcomes (PERMIT/DENY/DEFER) are enforced by the daemon.
- Human approve/deny decisions resolve DEFER tokens.

Tool naming behavior in this demo:
- Uses semantic tool names aligned with policy scopes.
- Governance ToolNode path appends execute-layer suffixes (for example /_execute_tool_sync).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from faramesh.adapters.langchain import install_langchain_interceptor
from langchain_core.tools import tool
from langgraph.prebuilt.tool_node import ToolNode

DEFER_TOKEN_RE = re.compile(r"token=([^,\)\s]+)")


@tool("http/get")
def http_get(url: str) -> str:
    """Fetch a URL and return a synthetic response body."""
    return f"fetched:{url}"


@tool("vault/probe")
def vault_probe(scope: str) -> str:
    """Probe a vault-like operation for the given scope."""
    return f"vault_probe_ok:{scope}"


@tool("payment/refund")
def payment_refund(amount: int) -> str:
    """Submit a payment refund amount."""
    return f"refund_submitted:{amount}"


@tool("shell/run")
def shell_run(command: str) -> str:
    """Simulate shell command execution for deny-path checks."""
    return f"shell_executed:{command}"


TOOLS = [http_get, vault_probe, payment_refund, shell_run]


@dataclass
class StepResult:
    step: str
    tool: str
    status: str
    message: str
    defer_token: str = ""


def emit(event: str, payload: dict[str, Any]) -> None:
    data = {"event": event, **payload}
    print(json.dumps(data), flush=True)


def _autopatch_frameworks() -> list[str]:
    runtime_mod = sys.modules.get("faramesh_autopatch_runtime")
    if runtime_mod is None:
        return []

    patched = getattr(runtime_mod, "_patched_frameworks", [])
    if isinstance(patched, list):
        return [str(x) for x in patched]
    return []


def _active_langgraph_patch_methods() -> list[str]:
    methods: list[str] = []
    for name in ("_execute_tool_sync", "_execute_tool_async", "_run_one", "_arun_one"):
        fn = getattr(ToolNode, name, None)
        if fn is None:
            continue
        if getattr(fn, "_faramesh_langchain_patched", False):
            methods.append(name)
    return methods


def _runtime(tool_call_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        state={"messages": []},
        config={},
        context=None,
        store=None,
        stream_writer=None,
        execution_info=None,
        server_info=None,
        tool_call_id=tool_call_id,
    )


def _invoke_toolnode(node: ToolNode, tool_call: dict[str, Any]) -> Any:
    """Invoke ToolNode across compatible signatures/shapes."""
    run_one = getattr(node, "_run_one", None)
    runtime = _runtime(str(tool_call.get("id", "")))

    if callable(run_one):
        for call in (
            lambda: run_one(tool_call, "tool_calls", runtime),
            lambda: run_one(tool_call, runtime),
            lambda: run_one(tool_call),
        ):
            try:
                return call()
            except TypeError:
                continue

    execute_sync = getattr(node, "_execute_tool_sync", None)
    if callable(execute_sync):
        request = SimpleNamespace(tool_call=tool_call)
        return execute_sync(request)

    raise RuntimeError("langgraph ToolNode dispatch method not found")


def run_agent_step(step: str, tool_name: str, tool_args: dict[str, Any]) -> StepResult:
    node = ToolNode(TOOLS)
    call = {
        "name": tool_name,
        "args": tool_args,
        "id": f"tc_{step}",
        "type": "tool_call",
    }

    try:
        out = _invoke_toolnode(node, call)
        return StepResult(
            step=step,
            tool=tool_name,
            status="executed",
            message=f"toolnode completed with content={getattr(out, 'content', '')}",
        )
    except Exception as exc:  # noqa: BLE001 - governance errors are surfaced here
        msg = str(exc)
        token = ""
        match = DEFER_TOKEN_RE.search(msg)
        if match:
            token = match.group(1)
        if "Faramesh DEFER" in msg:
            return StepResult(step=step, tool=tool_name, status="deferred", message=msg, defer_token=token)
        if "Faramesh DENY" in msg:
            return StepResult(step=step, tool=tool_name, status="denied", message=msg)
        return StepResult(step=step, tool=tool_name, status="error", message=msg)


def resolve_defer_token(step: str, token: str, approve: bool) -> str:
    bin_path = os.environ.get("FARAMESH_BIN", "faramesh")
    socket_path = os.environ.get("FARAMESH_SOCKET", "/tmp/faramesh.sock")
    decision = "approve" if approve else "deny"

    cmd = [bin_path, "agent", decision, token, "--socket", socket_path]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if completed.returncode != 0:
        emit(
            "defer_status",
            {
                "step": step,
                "status": "error",
                "decision": decision,
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            },
        )
        return "error"

    status = "approved" if approve else "denied"
    emit(
        "defer_status",
        {
            "step": step,
            "status": status,
            "decision": decision,
        },
    )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Run minimal LangGraph ToolNode drop-in interception checks")
    _ = parser.parse_args()

    patched_frameworks = _autopatch_frameworks()
    langgraph_patched_methods: list[str] = []
    langgraph_active_methods_before: list[str] = _active_langgraph_patch_methods()
    langgraph_active_methods_after: list[str] = []
    langgraph_patch_error = ""

    try:
        patched = install_langchain_interceptor(include_langgraph=True, fail_open=False)
        langgraph_patched_methods = [str(x) for x in patched.get("langgraph", [])]
        langgraph_active_methods_after = _active_langgraph_patch_methods()
    except Exception as exc:  # noqa: BLE001 - surfaced in startup payload
        langgraph_patch_error = str(exc)
        langgraph_active_methods_after = _active_langgraph_patch_methods()

    emit(
        "startup",
        {
            "note": "LangGraph ToolNode script with explicit ToolNode interception install.",
            "patched_frameworks": patched_frameworks,
            "langgraph_patched_methods": langgraph_patched_methods,
            "langgraph_active_methods_before": langgraph_active_methods_before,
            "langgraph_active_methods_after": langgraph_active_methods_after,
            "langgraph_patch_verified": bool(langgraph_active_methods_after),
            "langgraph_patch_error": langgraph_patch_error,
        },
    )

    results: list[StepResult] = []
    defer_outcomes: dict[str, str] = {}

    results.append(run_agent_step("permit_http", "http/get", {"url": "https://example.com"}))
    results.append(run_agent_step("permit_vault", "vault/probe", {"scope": "payments"}))
    results.append(run_agent_step("deny_shell", "shell/run", {"command": "cat /etc/passwd"}))
    results.append(run_agent_step("defer_approve", "payment/refund", {"amount": 700}))
    results.append(run_agent_step("defer_deny", "payment/refund", {"amount": 701}))

    for r in results:
        emit(
            "step",
            {
                "step": r.step,
                "tool": r.tool,
                "status": r.status,
                "message": r.message,
                "defer_token": r.defer_token,
            },
        )

        if r.step == "defer_approve" and r.status == "deferred" and r.defer_token:
            defer_outcomes[r.step] = resolve_defer_token(r.step, r.defer_token, approve=True)
        if r.step == "defer_deny" and r.status == "deferred" and r.defer_token:
            defer_outcomes[r.step] = resolve_defer_token(r.step, r.defer_token, approve=False)

    expected = {
        "permit_http": "executed",
        "permit_vault": "executed",
        "deny_shell": "denied",
        "defer_approve": "deferred",
        "defer_deny": "deferred",
    }
    got = {r.step: r.status for r in results}

    defer_expected = {
        "defer_approve": "approved",
        "defer_deny": "denied",
    }
    ok = all(got.get(k) == v for k, v in expected.items()) and all(
        defer_outcomes.get(k) == v for k, v in defer_expected.items()
    )

    emit(
        "summary",
        {
            "ok": ok,
            "expected": expected,
            "observed": got,
            "defer_expected": defer_expected,
            "defer_observed": defer_outcomes,
        },
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
