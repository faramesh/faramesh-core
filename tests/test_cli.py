import os
import subprocess
from pathlib import Path

import httpx

# run_server is defined in conftest.py and available at runtime
from conftest import run_server


def _run_cli(args, env, cwd):
    result = subprocess.run(
        ["python3", "-m", "faramesh.cli", *args],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return result


def test_cli_migrate_and_actions(tmp_path, base_policy):
    """Smoke test CLI migrate + list/get/allow/deny."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(base_policy)
    db_path = tmp_path / "cli.db"

    env = os.environ.copy()
    env.update(
        {
            "FARA_DB_BACKEND": "sqlite",
            "FARA_SQLITE_PATH": str(db_path),
            "FARA_POLICY_FILE": str(policy_file),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
    )
    cwd = Path(__file__).resolve().parents[2]

    # Migrate DB
    res = _run_cli(["migrate"], env=env, cwd=cwd)
    assert res.returncode == 0, res.stderr

    # Start server for action commands
    with run_server(tmp_path, base_policy) as base_url:
        env["FARA_API_BASE"] = base_url

        # Create pending action via API
        with httpx.Client(base_url=base_url, timeout=5.0) as client:
            r = client.post(
                "/v1/actions",
                json={"agent_id": "cli", "tool": "shell", "operation": "run", "params": {"cmd": "echo hi"}},
            )
            action = r.json()
            action_id = action["id"]

        # List
        res = _run_cli(["list", "--limit", "5"], env=env, cwd=cwd)
        assert res.returncode == 0, res.stderr

        # Get
        res = _run_cli(["get", action_id], env=env, cwd=cwd)
        assert res.returncode == 0, res.stderr

        # Approve (allow)
        res = _run_cli(["allow", action_id], env=env, cwd=cwd)
        assert res.returncode == 0, res.stderr

        # Deny a new action
        with httpx.Client(base_url=base_url, timeout=5.0) as client:
            r = client.post(
                "/v1/actions",
                json={"agent_id": "cli", "tool": "unknown", "operation": "do", "params": {}},
            )
            denied = r.json()
            denied_id = denied["id"]
        res = _run_cli(["deny", denied_id], env=env, cwd=cwd)
        # If already denied, CLI exits 0 after printing message
        assert res.returncode == 0, res.stderr


def test_cli_action_namespace(tmp_path, base_policy):
    """Test fara action submit/approve/deny/start/replay commands."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(base_policy)
    db_path = tmp_path / "cli.db"

    env = os.environ.copy()
    env.update(
        {
            "FARA_DB_BACKEND": "sqlite",
            "FARA_SQLITE_PATH": str(db_path),
            "FARA_POLICY_FILE": str(policy_file),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
    )
    cwd = Path(__file__).resolve().parents[2]

    # Migrate DB
    res = _run_cli(["migrate"], env=env, cwd=cwd)
    assert res.returncode == 0, res.stderr

    # Start server
    with run_server(tmp_path, base_policy) as base_url:
        env["FARA_API_BASE"] = base_url

        # Test action submit with --param parsing
        res = _run_cli(
            [
                "action", "submit",
                "test-agent",
                "shell",
                "run",
                "--param", "cmd=echo hello",
            ],
            env=env,
            cwd=cwd,
        )
        assert res.returncode == 0, f"stdout: {res.stdout}\nstderr: {res.stderr}"
        assert "Action submitted" in res.stdout or "pending_approval" in res.stdout or "allowed" in res.stdout

        # Test history command
        res = _run_cli(["history", "--limit", "5"], env=env, cwd=cwd)
        assert res.returncode == 0, res.stderr


def test_cli_apply_yaml(tmp_path, base_policy):
    """Test fara apply command with YAML file."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(base_policy)
    db_path = tmp_path / "cli.db"

    env = os.environ.copy()
    env.update(
        {
            "FARA_DB_BACKEND": "sqlite",
            "FARA_SQLITE_PATH": str(db_path),
            "FARA_POLICY_FILE": str(policy_file),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
    )
    cwd = Path(__file__).resolve().parents[2]

    # Migrate DB
    res = _run_cli(["migrate"], env=env, cwd=cwd)
    assert res.returncode == 0, res.stderr

    # Create action YAML file
    action_yaml = tmp_path / "action.yaml"
    action_yaml.write_text("""agent_id: test-agent
tool: http
operation: get
params:
  url: https://example.com
context:
  test: true
""")

    # Start server
    with run_server(tmp_path, base_policy) as base_url:
        env["FARA_API_BASE"] = base_url

        # Test apply command
        res = _run_cli(["apply", str(action_yaml)], env=env, cwd=cwd)
        assert res.returncode == 0, f"stdout: {res.stdout}\nstderr: {res.stderr}"
        assert "Action applied" in res.stdout or "pending_approval" in res.stdout or "allowed" in res.stdout
