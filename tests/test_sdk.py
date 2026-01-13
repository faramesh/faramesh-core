import os
import shutil
import subprocess
from pathlib import Path

import pytest

from faracore.sdk.client import ExecutionGovernorClient, GovernorConfig, GovernorError


def test_python_sdk_submit_and_get(server):
    client = ExecutionGovernorClient(GovernorConfig(base_url=server, agent_id="sdk-agent"))

    allowed = client.submit_action("http", "get", {"url": "https://example.com"})
    assert allowed["status"] == "allowed"

    pending = client.submit_action("shell", "run", {"cmd": "echo hi"})
    assert pending["status"] == "pending_approval"
    fetched = client.get_action(pending["id"])
    assert fetched["id"] == pending["id"]

    with pytest.raises(GovernorError):
        client.submit_action("unknown", "do", {})


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not available")
def test_node_sdk_submit_and_get(tmp_path, base_policy):
    """Minimal integration: run Node SDK against live server."""
    from conftest import run_server  # reuse helper

    with run_server(tmp_path, base_policy) as base_url:
        script = tmp_path / "sdk_test.js"
        module_path = (Path(__file__).resolve().parents[1] / "sdk/node/src/index.js").as_posix()
        script.write_text(
            f"""
const sdk = require("{module_path}");
const submitAction = sdk.submitAction;
const getAction = sdk.getAction;
const Config = sdk.Config;

if (typeof getAction !== 'function' || typeof submitAction !== 'function') {{
  console.error("SDK exports invalid", Object.keys(sdk));
  process.exit(1);
}}

(async () => {{
  const config = new Config({{ apiBase: "{base_url}", authToken: null, agentId: "node-agent" }});
  const allowed = await submitAction({{ agentId: "node-agent", tool: "http", operation: "get", params: {{ url: "https://example.com" }} }}, config);
  if (allowed.status !== "allowed") {{
    console.error("expected allowed", allowed);
    process.exit(1);
  }}
  const pending = await submitAction({{ agentId: "node-agent", tool: "shell", operation: "run", params: {{ cmd: "echo hi" }} }}, config);
  const fetched = await getAction(pending.id, config);
  if (fetched.id !== pending.id) {{
    console.error("mismatched id");
    process.exit(1);
  }}
  process.exit(0);
}})().catch((err) => {{
  console.error(err);
  process.exit(1);
}});
"""
        )

        env = os.environ.copy()
        proc = subprocess.run(["node", str(script)], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
