#!/usr/bin/env python3
"""Example: Batch submit multiple actions."""

from faracore import configure, submit_actions

configure(base_url="http://localhost:8000")

# Submit multiple actions at once
actions = submit_actions([
    {
        "agent_id": "agent1",
        "tool": "http",
        "operation": "get",
        "params": {"url": "https://example.com"},
    },
    {
        "agent_id": "agent2",
        "tool": "http",
        "operation": "get",
        "params": {"url": "https://example.org"},
    },
    {
        "agent_id": "agent3",
        "tool": "shell",
        "operation": "run",
        "params": {"cmd": "ls -la"},
    },
])

print(f"Submitted {len(actions)} actions:")
for i, action in enumerate(actions, 1):
    if "error" in action:
        print(f"  {i}. Error: {action['error']}")
    else:
        print(f"  {i}. Action {action['id']}: {action['status']}")
