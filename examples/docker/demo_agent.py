"""
Demo agent that submits actions to FaraCore.
"""

import os
import time
import sys

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from faracore.sdk.client import ExecutionGovernorClient


def main():
    api_base = os.getenv("FARA_API_BASE", "http://127.0.0.1:8000")
    agent_id = os.getenv("FARA_AGENT_ID", "demo-agent")
    
    client = ExecutionGovernorClient(api_base)
    
    print(f"Demo agent starting (agent_id: {agent_id})")
    print(f"Connecting to: {api_base}")
    
    # Submit a few actions
    actions = [
        {
            "tool": "http",
            "operation": "get",
            "params": {"url": "https://api.example.com/data"},
        },
        {
            "tool": "shell",
            "operation": "run",
            "params": {"cmd": "echo 'Hello from demo agent'"},
        },
    ]
    
    for action_spec in actions:
        try:
            print(f"\nSubmitting action: {action_spec['tool']} {action_spec['operation']}")
            action = client.submit_action(
                tool=action_spec["tool"],
                operation=action_spec["operation"],
                params=action_spec["params"],
                context={"agent_id": agent_id},
            )
            print(f"Action ID: {action['id']}")
            print(f"Status: {action['status']}")
            print(f"Decision: {action.get('decision', 'N/A')}")
            
            # If pending approval, wait a bit
            if action['status'] == 'pending_approval':
                print("Action requires approval. Waiting...")
                time.sleep(5)
                updated = client.get_action(action['id'])
                print(f"Updated status: {updated['status']}")
            
            time.sleep(2)
        except Exception as e:
            print(f"Error: {e}")
    
    print("\nDemo agent finished")


if __name__ == "__main__":
    main()
