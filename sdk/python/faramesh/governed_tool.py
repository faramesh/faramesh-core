"""Decorator for governing tool functions with Faramesh.

This module provides the `governed_tool` decorator that wraps functions
to submit them to Faramesh for policy evaluation before execution.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Dict, Optional

from .client import (
    submit_action,
    block_until_approved,
    wait_for_completion,
    FarameshDeniedError,
)


def governed_tool(
    agent_id: str,
    tool: str,
    operation: Optional[str] = None,
    *,
    block_until_done: bool = False,
    wait_timeout: int = 60,
    poll_interval: int = 1,
):
    """Decorator that submits function calls to Faramesh for governance.
    
    On function call:
    - Submits an action to Faramesh with agent_id, tool, operation (or function.__name__)
      params = {"args": args, "kwargs": kwargs}
    - If block_until_done is False:
      - Returns the action dict (status may be allowed/denied/pending_approval)
    - If block_until_done is True:
      - Uses wait_for_completion on the action id
      - Returns the final action object
    
    Args:
        agent_id: Agent identifier
        tool: Tool name (e.g., "shell", "http")
        operation: Operation name (defaults to function.__name__)
        block_until_done: If True, wait for completion before returning
        wait_timeout: Timeout in seconds for waiting (default: 60)
        poll_interval: Poll interval in seconds (default: 1)
    
    Example:
        >>> @governed_tool(agent_id="agent-1", tool="shell", operation="run", block_until_done=True)
        ... def dangerous_shell(cmd: str):
        ...     return cmd  # function body not actually used; we just model intent
        >>> 
        >>> result = dangerous_shell("echo hi")
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        op_name = operation or fn.__name__
        
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            # Submit action with function args/kwargs as params
            params = {
                "args": [repr(a) for a in args],
                "kwargs": kwargs,
            }
            
            action = submit_action(
                agent_id=agent_id,
                tool=tool,
                operation=op_name,
                params=params,
            )
            
            if block_until_done:
                # Wait for approval if needed
                if action.get("status") == "pending_approval":
                    try:
                        action = block_until_approved(
                            action["id"],
                            poll_interval=poll_interval,
                            timeout=wait_timeout,
                        )
                    except FarameshDeniedError:
                        raise
                
                # Wait for completion
                if action.get("status") in ("allowed", "approved"):
                    # Note: This assumes the action will be started externally
                    # or that start_action is called elsewhere
                    # For now, just wait if already executing
                    if action.get("status") == "executing":
                        action = wait_for_completion(
                            action["id"],
                            poll_interval=poll_interval,
                            timeout=wait_timeout,
                        )
            
            return action
        
        return wrapper
    
    return decorator
