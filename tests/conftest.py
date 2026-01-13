import os
import socket
import subprocess
import time
from contextlib import contextmanager
from typing import Optional
from pathlib import Path

import httpx
import pytest


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for_ready(base_url: str, timeout: float = 15.0) -> None:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(f"{base_url}/ready", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"Server at {base_url} did not become ready within {timeout}s")


@contextmanager
def run_server(tmp_path: Path, policy_text: str, auth_token: Optional[str] = None):
    """Run the FaraCore server in a subprocess for integration tests."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_text)
    db_path = tmp_path / "actions.db"

    port = _get_free_port()
    env = os.environ.copy()
    env.update(
        {
            "FARA_DB_BACKEND": "sqlite",
            "FARA_SQLITE_PATH": str(db_path),
            "FARA_POLICY_FILE": str(policy_file),
            "FARA_API_HOST": "127.0.0.1",
            "FARA_API_PORT": str(port),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
    )
    if auth_token:
        env["FARA_AUTH_TOKEN"] = auth_token

    cmd = [
        "python3",
        "-m",
        "uvicorn",
        "faracore.server.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]

    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_ready(base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture()
def base_policy() -> str:
    """Default policy for tests covering allow/deny/approval."""
    return """\
rules:
  - match:
      tool: "http"
      op: "*"
    allow: true
    description: "Allow HTTP"
  - match:
      tool: "shell"
      op: "*"
    require_approval: true
    description: "Shell requires approval"
  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Default deny"
"""


@pytest.fixture()
def server(tmp_path, base_policy):
    with run_server(tmp_path, base_policy) as url:
        yield url


@pytest.fixture()
def auth_server(tmp_path, base_policy):
    with run_server(tmp_path, base_policy, auth_token="secret-token") as url:
        yield url
