"""
LangChain integration for Faramesh - Governed Tool Wrapper

This module provides a wrapper that intercepts LangChain tool calls,
submits them to Faramesh for governance, and waits for approval before execution.
"""

from __future__ import annotations

import time
from typing import Any, Dict

# Use minimal client from integrations module (no external SDK needed)
from .._client import ExecutionGovernorClient


class GovernedTool:
    """
    Wrapper for LangChain tools that enforces Faramesh governance.
    
    Usage:
        from langchain.tools import ShellTool
        from faramesh.integrations.langchain import GovernedTool
        
        tool = ShellTool()
        governed = GovernedTool(
            tool=tool,
            client=ExecutionGovernorClient("http://127.0.0.1:8000"),
            agent_id="my-agent"
        )
        
        # Use governed tool in agent
        result = governed.run("ls -la")
    """
    
    def __init__(
        self,
        tool: Any,  # LangChain BaseTool
        client: ExecutionGovernorClient,
        agent_id: str,
        poll_interval: float = 2.0,
        max_wait_time: float = 300.0,
    ):
        """
        Initialize a governed tool wrapper.
        
        Args:
            tool: LangChain tool instance to wrap
            client: Faramesh ExecutionGovernorClient
            agent_id: Agent identifier for this tool
            poll_interval: Seconds between approval polls (default: 2.0)
            max_wait_time: Maximum seconds to wait for approval (default: 300.0)
        """
        self.tool = tool
        self.client = client
        self.agent_id = agent_id
        self.poll_interval = poll_interval
        self.max_wait_time = max_wait_time
    
    def _extract_tool_info(self) -> tuple[str, str, Dict[str, Any]]:
        """Extract tool name, operation, and params from LangChain tool."""
        # Try to get tool name
        tool_name = getattr(self.tool, 'name', 'unknown')
        if hasattr(self.tool, '_name'):
            tool_name = self.tool._name
        
        # For shell tools, operation is typically "run"
        operation = "run"
        if hasattr(self.tool, 'description'):
            # Try to infer operation from description
            desc = self.tool.description or ""
            if "shell" in desc.lower() or "command" in desc.lower():
                operation = "run"
        
        return tool_name, operation, {}
    
    def run(self, *args, **kwargs) -> str:
        """
        Execute the tool with Faramesh governance.
        
        This method:
        1. Submits the tool call to Faramesh
        2. Waits for approval if pending
        3. Executes the tool if allowed/approved
        4. Reports result back to Faramesh
        5. Returns the result or raises on denial
        """
        tool_name, operation, _ = self._extract_tool_info()
        
        # Build params from args/kwargs
        params = {}
        if args:
            # For shell tools, first arg is usually the command
            if tool_name.lower() in ('shell', 'bash', 'command'):
                params['cmd'] = str(args[0]) if args else ''
            else:
                params['args'] = list(args)
        params.update(kwargs)
        
        # Submit to Faramesh
        action = self.client.submit_action(
            tool=tool_name,
            operation=operation,
            params=params,
            context={"agent_id": self.agent_id, "langchain_tool": True},
        )
        
        action_id = action['id']
        status = action.get('status', '')
        decision = action.get('decision', '')
        
        # Handle decision
        if decision == 'deny' or status == 'denied':
            reason = action.get('reason', 'Action denied by policy')
            raise PermissionError(f"Action denied: {reason}")
        
        if status == 'pending_approval':
            # Poll until approved or denied
            start_time = time.time()
            while time.time() - start_time < self.max_wait_time:
                time.sleep(self.poll_interval)
                updated = self.client.get_action(action_id)
                updated_status = updated.get('status', '')
                
                if updated_status == 'approved' or updated_status == 'allowed':
                    break
                elif updated_status == 'denied':
                    reason = updated.get('reason', 'Action denied')
                    raise PermissionError(f"Action denied: {reason}")
                elif updated_status == 'pending_approval':
                    continue
                else:
                    # Unexpected status
                    break
        
        # Check final status
        final_action = self.client.get_action(action_id)
        final_status = final_action.get('status', '')
        
        if final_status not in ('approved', 'allowed'):
            raise PermissionError(f"Action not approved. Status: {final_status}")
        
        # Execute the actual tool
        try:
            result = self.tool.run(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
            raise
        
        finally:
            # Report result to Faramesh
            try:
                self.client.report_result(action_id, success=success, error=error)
            except Exception:
                pass  # Don't fail if reporting fails
        
        return result
    
    def __getattr__(self, name: str):
        """Delegate attribute access to wrapped tool."""
        return getattr(self.tool, name)


def wrap_tool(
    tool: Any,
    client: ExecutionGovernorClient,
    agent_id: str,
    **kwargs
) -> GovernedTool:
    """
    Convenience function to wrap a LangChain tool with governance.
    
    Args:
        tool: LangChain tool instance
        client: Faramesh ExecutionGovernorClient
        agent_id: Agent identifier
        **kwargs: Additional arguments for GovernedTool
    
    Returns:
        GovernedTool instance
    """
    return GovernedTool(tool=tool, client=client, agent_id=agent_id, **kwargs)
