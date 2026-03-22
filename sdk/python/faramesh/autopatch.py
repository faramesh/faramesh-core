"""
Faramesh Auto-Patcher — framework dispatch point interception.

When FARAMESH_AUTOLOAD=1 is set (by `faramesh run`), this module
patches the single dispatch choke point in detected AI frameworks
so every tool call flows through Faramesh governance.

Supported frameworks and their patch points:
  - LangChain/LangGraph:      BaseTool.run / BaseTool.arun
  - CrewAI:                   BaseTool._run
  - AutoGen/AG2:              ConversableAgent._execute_tool_call
  - OpenAI Agents SDK:        FunctionTool.on_invoke_tool
  - Pydantic AI:              Tool.run
  - Smolagents:               Tool.__call__
  - Google ADK:               FunctionTool.call / BaseTool.run_async
  - LlamaIndex:               FunctionTool.call / BaseTool.call
  - AWS Strands Agents:       tool decorator via agent.tool.run
  - Haystack:                 Pipeline.run

Usage:
  # Automatic (set by faramesh run):
  FARAMESH_AUTOLOAD=1 python agent.py

  # Manual:
  import faramesh.autopatch
  faramesh.autopatch.install()
"""
from __future__ import annotations

import functools
import importlib
import logging
import os
import sys
from typing import Any, Callable

logger = logging.getLogger("faramesh.autopatch")

_installed = False
_patched_frameworks: list[str] = []


def install() -> list[str]:
    """Install governance patches on all detected frameworks. Idempotent."""
    global _installed
    if _installed:
        return _patched_frameworks

    _installed = True
    patched: list[str] = []

    for name, patcher in _PATCHERS.items():
        try:
            if patcher():
                patched.append(name)
                logger.info("faramesh: patched %s dispatch point", name)
        except Exception as exc:
            logger.debug("faramesh: %s not available (%s)", name, exc)

    _patched_frameworks.extend(patched)
    return patched


def _govern_call(tool_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Submit a tool call to the Faramesh daemon for governance.

    Tries socket-based governance first (fastest, used with `faramesh run`),
    falls back to the HTTP SDK client.
    """
    socket_path = os.environ.get("FARAMESH_SOCKET", "/tmp/faramesh.sock")

    if os.path.exists(socket_path):
        return _govern_via_socket(socket_path, tool_id, args)

    try:
        from faramesh.gate import gate_decide

        agent_id = os.environ.get("FARAMESH_AGENT_ID", "auto-patched")
        parts = tool_id.rsplit("/", 1)
        tool = parts[0] if len(parts) > 1 else tool_id
        operation = parts[1] if len(parts) > 1 else "invoke"

        decision = gate_decide(agent_id, tool, operation, args)
        outcome = (decision.outcome or "").upper()
        if outcome in ("EXECUTE", "PERMIT"):
            return {"effect": "PERMIT"}
        if outcome in ("HALT", "DENY"):
            return {"effect": "DENY", "reason_code": decision.reason_code}
        if outcome in ("ABSTAIN", "DEFER", "PENDING"):
            return {"effect": "DEFER", "defer_token": getattr(decision, "provenance_id", "")}
        return {"effect": "PERMIT"}
    except ImportError:
        logger.warning("faramesh SDK not available; auto-patch pass-through")
        return {"effect": "PERMIT"}
    except Exception as exc:
        logger.error("faramesh govern error (fail-closed): %s", exc)
        raise RuntimeError(f"Faramesh governance denied: {exc}") from exc


def _govern_via_socket(socket_path: str, tool_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Governance via Unix domain socket to faramesh daemon."""
    import json
    import socket as _socket

    parts = tool_id.rsplit("/", 1)
    tool = parts[0] if len(parts) > 1 else tool_id
    operation = parts[1] if len(parts) > 1 else "invoke"

    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "govern",
        "params": {
            "agent_id": os.environ.get("FARAMESH_AGENT_ID", "auto-patched"),
            "tool": tool,
            "operation": operation,
            "args": args,
        },
    }).encode("utf-8")

    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(socket_path)
        sock.sendall(payload + b"\n")
        resp_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp_data += chunk
            if b"\n" in resp_data:
                break
        sock.close()

        resp = json.loads(resp_data.strip())
        result = resp.get("result", {})
        effect = result.get("effect", "PERMIT").upper()
        return {
            "effect": effect,
            "reason_code": result.get("reason_code", ""),
            "defer_token": result.get("defer_token", ""),
        }
    except Exception as exc:
        logger.error("faramesh socket govern error (fail-closed): %s", exc)
        raise RuntimeError(f"Faramesh governance denied: {exc}") from exc


def _wrap_method(cls: type, method_name: str, framework: str, tool_id_fn: Callable) -> bool:
    """Wrap a class method with Faramesh governance. Returns True if patched."""
    original = getattr(cls, method_name, None)
    if original is None:
        return False
    if getattr(original, "_faramesh_patched", False):
        return False

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        tid = tool_id_fn(self, args, kwargs)
        call_args = _extract_args(args, kwargs)
        result = _govern_call(tid, call_args)
        effect = result.get("effect", "PERMIT")
        if effect == "DENY":
            reason = result.get("reason_code", "POLICY_DENY")
            raise RuntimeError(f"Faramesh DENY: {reason} (tool={tid})")
        if effect == "DEFER":
            token = result.get("defer_token", "")
            raise RuntimeError(f"Faramesh DEFER: approval required (token={token}, tool={tid})")
        return original(self, *args, **kwargs)

    wrapper._faramesh_patched = True
    setattr(cls, method_name, wrapper)
    return True


def _extract_args(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Build a flat dict from positional and keyword arguments."""
    result = dict(kwargs)
    if args:
        if len(args) == 1 and isinstance(args[0], (str, dict)):
            result["input"] = args[0]
        else:
            result["_positional"] = list(args)
    return result


# --- Framework-specific patchers ---

def _patch_langchain() -> bool:
    """Patch LangChain BaseTool.run and arun."""
    try:
        mod = importlib.import_module("langchain_core.tools")
    except ImportError:
        mod = importlib.import_module("langchain.tools")

    cls = getattr(mod, "BaseTool")
    tool_id = lambda self, a, kw: getattr(self, "name", type(self).__name__)
    ok1 = _wrap_method(cls, "run", "langchain", tool_id)
    ok2 = _wrap_method(cls, "arun", "langchain", tool_id)
    return ok1 or ok2


def _patch_crewai() -> bool:
    """Patch CrewAI BaseTool._run."""
    mod = importlib.import_module("crewai.tools")
    cls = getattr(mod, "BaseTool")
    tool_id = lambda self, a, kw: getattr(self, "name", type(self).__name__)
    return _wrap_method(cls, "_run", "crewai", tool_id)


def _patch_autogen() -> bool:
    """Patch AutoGen/AG2 ConversableAgent tool execution."""
    mod = importlib.import_module("autogen")
    cls = getattr(mod, "ConversableAgent")
    tool_id = lambda self, a, kw: kw.get("name", a[0] if a else "unknown")
    return _wrap_method(cls, "_execute_tool_call", "autogen", tool_id)


def _patch_openai_agents() -> bool:
    """Patch OpenAI Agents SDK FunctionTool."""
    mod = importlib.import_module("agents")
    cls = getattr(mod, "FunctionTool")
    tool_id = lambda self, a, kw: getattr(self, "name", type(self).__name__)
    return _wrap_method(cls, "on_invoke_tool", "openai-agents", tool_id)


def _patch_pydantic_ai() -> bool:
    """Patch Pydantic AI Tool.run and the Agent-level tool dispatch.

    Pydantic AI tools are registered via @agent.tool / @agent.tool_plain
    decorators, which create Tool objects. The dispatch point is Tool.run()
    which receives RunContext. We also patch Agent._call_tool for full
    coverage of the retry/validation layer.
    """
    mod = importlib.import_module("pydantic_ai.tools")
    cls = getattr(mod, "Tool")
    tool_id = lambda self, a, kw: getattr(self, "name", getattr(self, "function_name", type(self).__name__))
    ok1 = _wrap_method(cls, "run", "pydantic-ai", tool_id)

    try:
        agent_mod = importlib.import_module("pydantic_ai.agent")
        agent_cls = getattr(agent_mod, "Agent", None)
        if agent_cls:
            agent_tool_id = lambda self, a, kw: kw.get("tool_name", a[0] if a else "pydantic-ai/agent")
            ok2 = _wrap_method(agent_cls, "_call_tool", "pydantic-ai", agent_tool_id)
            return ok1 or ok2
    except (ImportError, AttributeError):
        pass
    return ok1


def _patch_google_adk() -> bool:
    """Patch Google Agent Development Kit (ADK) tool dispatch.

    ADK wraps plain Python functions as FunctionTool objects when assigned
    to an Agent's tools list. The dispatch flows through:
      - google.adk.tools.function_tool.FunctionTool.call()
      - google.adk.tools.base_tool.BaseTool.run_async()
    """
    ok = False
    for mod_path, cls_name, method in [
        ("google.adk.tools.function_tool", "FunctionTool", "call"),
        ("google.adk.tools.base_tool", "BaseTool", "run_async"),
    ]:
        try:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            tool_id = lambda self, a, kw: getattr(self, "name", getattr(self, "_name", type(self).__name__))
            if _wrap_method(cls, method, "google-adk", tool_id):
                ok = True
        except (ImportError, AttributeError):
            continue
    return ok


def _patch_llamaindex() -> bool:
    """Patch LlamaIndex tool dispatch.

    LlamaIndex tools flow through:
      - llama_index.core.tools.FunctionTool.call()  (primary)
      - llama_index.core.tools.BaseTool.call()      (base class)
      - llama_index.core.tools.AsyncBaseTool.acall() (async variant)
    """
    ok = False
    for mod_path in ["llama_index.core.tools", "llama_index.core.tools.function_tool"]:
        try:
            mod = importlib.import_module(mod_path)
            for cls_name in ["FunctionTool", "BaseTool", "AsyncBaseTool"]:
                cls = getattr(mod, cls_name, None)
                if cls is None:
                    continue
                tool_id = lambda self, a, kw: getattr(
                    self, "name",
                    getattr(getattr(self, "metadata", None), "name", type(self).__name__)
                )
                for method in ["call", "acall"]:
                    if hasattr(cls, method):
                        if _wrap_method(cls, method, "llamaindex", tool_id):
                            ok = True
        except (ImportError, AttributeError):
            continue
    return ok


def _patch_strands_agents() -> bool:
    """Patch AWS Strands Agents tool dispatch.

    Strands Agents (AWS Bedrock AgentCore's framework) uses:
      - strands.tools.decorator-based tool registration
      - strands.agent.Agent tool execution path
    The dispatch flows through Agent._run_tool() or tool.__call__().
    """
    ok = False
    try:
        mod = importlib.import_module("strands.agent")
        cls = getattr(mod, "Agent", None)
        if cls:
            tool_id = lambda self, a, kw: kw.get("tool_name", a[0] if a else "strands/agent")
            for method in ["_run_tool", "tool_handler"]:
                if hasattr(cls, method):
                    if _wrap_method(cls, method, "strands-agents", tool_id):
                        ok = True
    except (ImportError, AttributeError):
        pass

    try:
        tools_mod = importlib.import_module("strands.tools")
        tool_cls = getattr(tools_mod, "FunctionTool", None) or getattr(tools_mod, "Tool", None)
        if tool_cls:
            tool_id = lambda self, a, kw: getattr(self, "tool_name", getattr(self, "name", type(self).__name__))
            if _wrap_method(tool_cls, "__call__", "strands-agents", tool_id):
                ok = True
    except (ImportError, AttributeError):
        pass
    return ok


def _patch_smolagents() -> bool:
    """Patch HuggingFace Smolagents Tool.__call__."""
    mod = importlib.import_module("smolagents")
    cls = getattr(mod, "Tool")
    tool_id = lambda self, a, kw: getattr(self, "name", type(self).__name__)
    return _wrap_method(cls, "__call__", "smolagents", tool_id)


def _patch_haystack() -> bool:
    """Patch Haystack pipeline run (component-level)."""
    mod = importlib.import_module("haystack")
    cls = getattr(mod, "Pipeline", None)
    if cls is None:
        return False
    tool_id = lambda self, a, kw: "haystack/pipeline"
    return _wrap_method(cls, "run", "haystack", tool_id)


_PATCHERS: dict[str, Callable[[], bool]] = {
    "langchain": _patch_langchain,
    "crewai": _patch_crewai,
    "autogen": _patch_autogen,
    "openai-agents": _patch_openai_agents,
    "pydantic-ai": _patch_pydantic_ai,
    "google-adk": _patch_google_adk,
    "llamaindex": _patch_llamaindex,
    "strands-agents": _patch_strands_agents,
    "smolagents": _patch_smolagents,
    "haystack": _patch_haystack,
}


# Auto-install when FARAMESH_AUTOLOAD=1
if os.environ.get("FARAMESH_AUTOLOAD") == "1":
    install()
