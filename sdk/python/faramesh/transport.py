"""Governance transport: Unix socket daemon or HTTPS remote evaluate."""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional

import urllib.error
import urllib.request


@dataclass
class Transport:
    mode: str
    socket_path: str = ""
    remote_url: str = ""
    token: str = ""


def detect_transport() -> Transport:
    remote = (os.environ.get("FARAMESH_REMOTE_URL") or "").strip().rstrip("/")
    if remote:
        return Transport(
            mode="remote",
            remote_url=remote,
            token=(os.environ.get("FARAMESH_TOKEN") or "").strip(),
        )
    default_sock = os.path.join(
        os.path.expanduser("~"), ".faramesh", "runtime", "faramesh.sock"
    )
    sock = (os.environ.get("FARAMESH_SOCKET") or default_sock).strip()
    if os.path.exists(sock):
        return Transport(mode="socket", socket_path=sock)
    base = (os.environ.get("FARAMESH_BASE_URL") or "").strip().rstrip("/")
    if base:
        return Transport(
            mode="remote",
            remote_url=base,
            token=(os.environ.get("FARAMESH_TOKEN") or "").strip(),
        )
    raise RuntimeError(
        f"no governance transport: set FARAMESH_SOCKET ({sock} missing) or FARAMESH_REMOTE_URL"
    )


def govern_via_transport(
    transport: Transport,
    tool_id: str,
    args: Dict[str, Any],
    *,
    agent_id: Optional[str] = None,
    action_type: str = "tool_call",
) -> Dict[str, Any]:
    agent_id = agent_id or os.environ.get("FARAMESH_AGENT_ID", "auto-patched")
    parts = tool_id.rsplit("/", 1)
    tool = parts[0] if len(parts) > 1 else tool_id
    operation = parts[1] if len(parts) > 1 else "invoke"
    if transport.mode == "remote":
        return _govern_remote(transport, agent_id, tool, operation, args, action_type)
    return _govern_socket(transport.socket_path, agent_id, tool, operation, args, action_type)


def _govern_socket(
    socket_path: str,
    agent_id: str,
    tool: str,
    operation: str,
    args: Dict[str, Any],
    action_type: str,
) -> Dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "govern",
        "params": {
            "agent_id": agent_id,
            "tool": tool,
            "operation": operation,
            "args": args,
            "action_type": action_type,
            "principal_token": os.environ.get("FARAMESH_PRINCIPAL_TOKEN", ""),
        },
    }
    body = (json.dumps(payload) + "\n").encode("utf-8")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(30.0)
        conn.connect(socket_path)
        conn.sendall(body)
        data = conn.recv(65536)
    finally:
        conn.close()
    resp = json.loads(data.decode("utf-8"))
    if resp.get("error"):
        err = resp["error"]
        msg = err.get("message", err) if isinstance(err, dict) else err
        raise RuntimeError(f"socket govern: {msg}")
    result = resp.get("result") or {}
    out: Dict[str, Any] = {
        "effect": (result.get("effect") or "").upper(),
        "reason_code": result.get("reason_code", ""),
        "defer_token": result.get("defer_token", ""),
    }
    if isinstance(result.get("structured_denial"), dict):
        out["structured_denial"] = result["structured_denial"]
    return out


def _govern_remote(
    transport: Transport,
    agent_id: str,
    tool: str,
    operation: str,
    args: Dict[str, Any],
    action_type: str,
) -> Dict[str, Any]:
    car = {
        "agent_id": agent_id,
        "tool_id": f"{tool}/{operation}",
        "action_type": action_type,
        "args": args,
    }
    req = urllib.request.Request(
        transport.remote_url + "/v1/evaluate",
        data=json.dumps(car).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if transport.token:
        req.add_header("Authorization", f"Bearer {transport.token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            decision = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"remote evaluate: HTTP {exc.code}") from exc
    effect = (decision.get("effect") or decision.get("outcome") or "").upper()
    return {
        "effect": effect,
        "reason_code": decision.get("reason_code", ""),
        "defer_token": decision.get("defer_token", decision.get("provenance_id", "")),
    }
