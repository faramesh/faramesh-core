#!/usr/bin/env python3
"""Example: Submit action and wait for completion."""

from faracore import configure, submit_and_wait

configure(base_url="http://localhost:8000")

# Submit action and wait for completion (with auto-approval)
action = submit_and_wait(
    "my-agent",
    "http",
    "get",
    {"url": "https://example.com"},
    context={"source": "example"},
    poll_interval=1.0,
    timeout=60.0,
    auto_approve=True,
)

print(f"Action completed: {action['id']}")
print(f"Final status: {action['status']}")
print(f"Reason: {action.get('reason', 'N/A')}")
