from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Iterator


def send_json_request(socket_path: Path, payload: dict[str, object], timeout_seconds: float = 3.0) -> dict[str, object]:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout_seconds)
        conn.connect(str(socket_path))
        conn.sendall(raw)

        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

    if not data:
        raise RuntimeError("empty response from daemon socket")

    line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    if not line:
        raise RuntimeError("empty JSON line response from daemon socket")
    parsed = json.loads(line)
    if not isinstance(parsed, dict):
        raise RuntimeError("daemon response must be a JSON object")
    return parsed


def stream_json_lines(socket_path: Path, payload: dict[str, object], timeout_seconds: float = 5.0) -> Iterator[dict[str, object]]:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout_seconds)
        conn.connect(str(socket_path))
        conn.sendall(raw)

        reader = conn.makefile("r", encoding="utf-8")
        for line in reader:
            text = line.strip()
            if not text:
                continue
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                yield parsed
