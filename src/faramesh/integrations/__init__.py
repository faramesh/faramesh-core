"""
Faramesh Integrations - One-line governance for any agent framework

Drop-in governance for LangChain, CrewAI, AutoGen, MCP, and more.

Quick Start:
    # LangChain
    from faramesh.integrations import govern_langchain_tool
    tool = govern_langchain_tool(ShellTool(), agent_id="my-agent")
    
    # CrewAI
    from faramesh.integrations import govern_crewai_tool
    tool = govern_crewai_tool(YourTool(), agent_id="my-agent")
    
    # AutoGen
    from faramesh.integrations import govern_autogen_function
    func = govern_autogen_function(my_function, agent_id="my-agent")
    
    # MCP
    from faramesh.integrations import govern_mcp_tool
    tool = govern_mcp_tool(mcp_tool, agent_id="my-agent")
"""

from typing import Any, Optional

# Use minimal client included in core (no external SDK dependency needed)
# Users can install faramesh-sdk for full SDK features, but integrations work without it
from ._client import ExecutionGovernorClient

# Import LangChain integration
from .langchain.governed_tool import GovernedTool as LangChainGovernedTool

# Lazy imports for optional dependencies
_crewai_available = False
_autogen_available = False
_mcp_available = False

try:
    import crewai  # noqa: F401
    _crewai_available = True
except ImportError:
    pass

try:
    import autogen  # noqa: F401
    _autogen_available = True
except ImportError:
    pass

try:
    import mcp  # noqa: F401
    _mcp_available = True
except ImportError:
    pass


def _get_client(base_url: Optional[str] = None, token: Optional[str] = None) -> ExecutionGovernorClient:
    """Get or create Faramesh client."""
    if base_url is None:
        base_url = "http://127.0.0.1:8000"
    return ExecutionGovernorClient(base_url, token=token)


# ============================================================================
# LangChain Integration (One-liner)
# ============================================================================

def govern_langchain_tool(
    tool: Any,
    agent_id: str,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    **kwargs
) -> LangChainGovernedTool:
    """
    One-line governance for LangChain tools.
    
    Args:
        tool: LangChain tool instance (e.g., ShellTool, HTTPTool)
        agent_id: Agent identifier
        base_url: Faramesh server URL (default: http://127.0.0.1:8000)
        **kwargs: Additional arguments for GovernedTool
    
    Returns:
        GovernedTool wrapper
    
    Example:
        from langchain.tools import ShellTool
        from faramesh.integrations import govern_langchain_tool
        
        tool = govern_langchain_tool(ShellTool(), agent_id="my-agent")
        result = tool.run("ls -la")
    """
    client = _get_client(base_url, token=token)
    return LangChainGovernedTool(
        tool=tool,
        client=client,
        agent_id=agent_id,
        **kwargs
    )


# ============================================================================
# CrewAI Integration
# ============================================================================

class CrewAIGovernedTool:
    """Wrapper for CrewAI tools with Faramesh governance."""
    
    def __init__(
        self,
        tool: Any,
        client: ExecutionGovernorClient,
        agent_id: str,
        poll_interval: float = 2.0,
        max_wait_time: float = 300.0,
    ):
        self.tool = tool
        self.client = client
        self.agent_id = agent_id
        self.poll_interval = poll_interval
        self.max_wait_time = max_wait_time
    
    def _execute(self, *args, **kwargs):
        """Execute tool with governance."""
        import time
        
        # Extract tool info
        tool_name = getattr(self.tool, 'name', 'unknown')
        operation = "run"
        
        # Build params
        params = {}
        if args:
            params['args'] = list(args)
        params.update(kwargs)
        
        # Submit to Faramesh
        action = self.client.submit_action(
            tool=tool_name,
            operation=operation,
            params=params,
            context={"agent_id": self.agent_id, "crewai": True},
        )
        
        action_id = action['id']
        status = action.get('status', '')
        decision = action.get('decision', '')
        
        # Handle decision
        if decision == 'deny' or status == 'denied':
            reason = action.get('reason', 'Action denied by policy')
            raise PermissionError(f"Action denied: {reason}")
        
        if status == 'pending_approval':
            # Poll for approval
            start_time = time.time()
            while time.time() - start_time < self.max_wait_time:
                time.sleep(self.poll_interval)
                updated = self.client.get_action(action_id)
                updated_status = updated.get('status', '')
                
                if updated_status in ('approved', 'allowed'):
                    break
                elif updated_status == 'denied':
                    reason = updated.get('reason', 'Action denied')
                    raise PermissionError(f"Action denied: {reason}")
        
        # Execute tool
        try:
            result = self.tool._execute(*args, **kwargs)
            self.client.report_result(action_id, success=True, result=result)
            return result
        except Exception as e:
            self.client.report_result(action_id, success=False, error=str(e))
            raise
    
    def __getattr__(self, name: str):
        """Delegate attribute access to wrapped tool."""
        return getattr(self.tool, name)


def govern_crewai_tool(
    tool: Any,
    agent_id: str,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    **kwargs
) -> CrewAIGovernedTool:
    """
    One-line governance for CrewAI tools.
    
    Args:
        tool: CrewAI tool instance
        agent_id: Agent identifier
        base_url: Faramesh server URL (default: http://127.0.0.1:8000)
        **kwargs: Additional arguments for CrewAIGovernedTool
    
    Returns:
        CrewAIGovernedTool wrapper
    
    Example:
        from crewai_tools import FileReadTool
        from faramesh.integrations import govern_crewai_tool
        
        tool = govern_crewai_tool(FileReadTool(), agent_id="my-agent")
        result = tool._execute("file.txt")
    """
    if not _crewai_available:
        raise ImportError(
            "CrewAI not installed. Install with: pip install crewai"
        )
    client = _get_client(base_url, token=token)
    return CrewAIGovernedTool(
        tool=tool,
        client=client,
        agent_id=agent_id,
        **kwargs
    )


# ============================================================================
# AutoGen Integration
# ============================================================================

def govern_autogen_function(
    func: callable,
    agent_id: str,
    tool_name: Optional[str] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    poll_interval: float = 2.0,
    max_wait_time: float = 300.0,
):
    """
    One-line governance for AutoGen functions.
    
    Args:
        func: Function to govern
        agent_id: Agent identifier
        tool_name: Tool name (default: function name)
        base_url: Faramesh server URL (default: http://127.0.0.1:8000)
        poll_interval: Seconds between approval polls
        max_wait_time: Maximum seconds to wait for approval
    
    Returns:
        Governed function wrapper
    
    Example:
        from faramesh.integrations import govern_autogen_function
        
        def my_function(url: str) -> str:
            import requests
            return requests.get(url).text
        
        governed_func = govern_autogen_function(
            my_function,
            agent_id="my-agent",
            tool_name="http_get"
        )
        
        # Use in AutoGen agent
        agent = autogen.AssistantAgent(
            name="assistant",
            system_message="You are a helpful assistant.",
            function_map={"http_get": governed_func}
        )
    """
    if not _autogen_available:
        raise ImportError(
            "AutoGen not installed. Install with: pip install pyautogen"
        )
    
    import functools
    import time
    
    client = _get_client(base_url)
    tool_name = tool_name or func.__name__
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Build params
        params = {}
        if args:
            params['args'] = list(args)
        params.update(kwargs)
        
        # Submit to Faramesh
        action = client.submit_action(
            tool=tool_name,
            operation="call",
            params=params,
            context={"agent_id": agent_id, "autogen": True},
        )
        
        action_id = action['id']
        status = action.get('status', '')
        decision = action.get('decision', '')
        
        # Handle decision
        if decision == 'deny' or status == 'denied':
            reason = action.get('reason', 'Action denied by policy')
            raise PermissionError(f"Action denied: {reason}")
        
        if status == 'pending_approval':
            # Poll for approval
            start_time = time.time()
            while time.time() - start_time < max_wait_time:
                time.sleep(poll_interval)
                updated = client.get_action(action_id)
                updated_status = updated.get('status', '')
                
                if updated_status in ('approved', 'allowed'):
                    break
                elif updated_status == 'denied':
                    reason = updated.get('reason', 'Action denied')
                    raise PermissionError(f"Action denied: {reason}")
        
        # Execute function
        try:
            result = func(*args, **kwargs)
            client.report_result(action_id, success=True, result=result)
            return result
        except Exception as e:
            client.report_result(action_id, success=False, error=str(e))
            raise
    
    return wrapper


# ============================================================================
# MCP (Model Context Protocol) Integration
# ============================================================================

class MCPGovernedTool:
    """Wrapper for MCP tools with Faramesh governance."""
    
    def __init__(
        self,
        tool: Any,
        client: ExecutionGovernorClient,
        agent_id: str,
        poll_interval: float = 2.0,
        max_wait_time: float = 300.0,
    ):
        self.tool = tool
        self.client = client
        self.agent_id = agent_id
        self.poll_interval = poll_interval
        self.max_wait_time = max_wait_time
    
    def __call__(self, *args, **kwargs):
        """Execute tool with governance."""
        import time
        
        # Extract tool info
        tool_name = getattr(self.tool, 'name', getattr(self.tool, '__name__', 'unknown'))
        operation = "call"
        
        # Build params
        params = {}
        if args:
            params['args'] = list(args)
        params.update(kwargs)
        
        # Submit to Faramesh
        action = self.client.submit_action(
            tool=tool_name,
            operation=operation,
            params=params,
            context={"agent_id": self.agent_id, "mcp": True},
        )
        
        action_id = action['id']
        status = action.get('status', '')
        decision = action.get('decision', '')
        
        # Handle decision
        if decision == 'deny' or status == 'denied':
            reason = action.get('reason', 'Action denied by policy')
            raise PermissionError(f"Action denied: {reason}")
        
        if status == 'pending_approval':
            # Poll for approval
            start_time = time.time()
            while time.time() - start_time < self.max_wait_time:
                time.sleep(self.poll_interval)
                updated = self.client.get_action(action_id)
                updated_status = updated.get('status', '')
                
                if updated_status in ('approved', 'allowed'):
                    break
                elif updated_status == 'denied':
                    reason = updated.get('reason', 'Action denied')
                    raise PermissionError(f"Action denied: {reason}")
        
        # Execute tool
        try:
            if callable(self.tool):
                result = self.tool(*args, **kwargs)
            else:
                result = getattr(self.tool, 'call', lambda *a, **kw: None)(*args, **kwargs)
            self.client.report_result(action_id, success=True, result=result)
            return result
        except Exception as e:
            self.client.report_result(action_id, success=False, error=str(e))
            raise
    
    def __getattr__(self, name: str):
        """Delegate attribute access to wrapped tool."""
        return getattr(self.tool, name)


def govern_mcp_tool(
    tool: Any,
    agent_id: str,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    **kwargs
) -> MCPGovernedTool:
    """
    One-line governance for MCP tools.
    
    Args:
        tool: MCP tool instance or callable
        agent_id: Agent identifier
        base_url: Faramesh server URL (default: http://127.0.0.1:8000)
        **kwargs: Additional arguments for MCPGovernedTool
    
    Returns:
        MCPGovernedTool wrapper
    
    Example:
        from faramesh.integrations import govern_mcp_tool
        
        def my_mcp_tool(query: str) -> str:
            # Your tool logic
            return f"Result: {query}"
        
        tool = govern_mcp_tool(my_mcp_tool, agent_id="my-agent")
        result = tool("search query")
    """
    client = _get_client(base_url)
    return MCPGovernedTool(
        tool=tool,
        client=client,
        agent_id=agent_id,
        **kwargs
    )


# ============================================================================
# Universal One-Liner (works with any tool)
# ============================================================================

def govern(
    tool: Any,
    agent_id: str,
    tool_name: Optional[str] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    framework: Optional[str] = None,
    **kwargs
):
    """
    Universal one-liner governance - auto-detects framework.
    
    Args:
        tool: Tool instance or function
        agent_id: Agent identifier
        tool_name: Tool name (default: auto-detected)
        base_url: Faramesh server URL (default: http://127.0.0.1:8000)
        framework: Framework name ("langchain", "crewai", "autogen", "mcp", or None for auto-detect)
        **kwargs: Additional arguments
    
    Returns:
        Governed tool wrapper
    
    Example:
        from faramesh.integrations import govern
        
        # Auto-detects LangChain
        tool = govern(ShellTool(), agent_id="my-agent")
        
        # Auto-detects CrewAI
        tool = govern(CrewAITool(), agent_id="my-agent")
        
        # Explicit framework
        tool = govern(my_func, agent_id="my-agent", framework="autogen")
    """
    # Auto-detect framework if not specified
    if framework is None:
        tool_type = type(tool).__name__
        tool_module = type(tool).__module__
        
        if 'langchain' in tool_module or 'langchain' in str(tool_type).lower():
            framework = "langchain"
        elif 'crewai' in tool_module or 'crewai' in str(tool_type).lower():
            framework = "crewai"
        elif callable(tool) and not hasattr(tool, 'run') and not hasattr(tool, '_execute'):
            framework = "autogen"
        else:
            framework = "mcp"
    
    # Route to appropriate integration
    if framework == "langchain":
        return govern_langchain_tool(tool, agent_id, base_url, token=token, **kwargs)
    elif framework == "crewai":
        return govern_crewai_tool(tool, agent_id, base_url, token=token, **kwargs)
    elif framework == "autogen":
        return govern_autogen_function(tool, agent_id, tool_name, base_url, token=token, **kwargs)
    else:
        return govern_mcp_tool(tool, agent_id, base_url, token=token, **kwargs)


__all__ = [
    # LangChain
    "govern_langchain_tool",
    "LangChainGovernedTool",
    
    # CrewAI
    "govern_crewai_tool",
    "CrewAIGovernedTool",
    
    # AutoGen
    "govern_autogen_function",
    
    # MCP
    "govern_mcp_tool",
    "MCPGovernedTool",
    
    # Universal
    "govern",
]
