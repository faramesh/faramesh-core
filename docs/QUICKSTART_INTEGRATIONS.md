# Quick Start: Framework Integrations

Add Faramesh governance to any agent framework in **one line**.

## Prerequisites

```bash
# Install Faramesh
pip install faramesh

# Start Faramesh server
faramesh serve
```

## LangChain

```bash
pip install langchain
```

```python
from langchain.tools import ShellTool
from faramesh.integrations import govern_langchain_tool

# One line!
tool = govern_langchain_tool(ShellTool(), agent_id="my-agent")

# Use in agent
from langchain.agents import initialize_agent, AgentType

agent = initialize_agent(
    tools=[tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
)
```

**Full example:** [`examples/langchain/governed_agent.py`](examples/langchain/governed_agent.py)

## CrewAI

```bash
pip install crewai crewai-tools
```

```python
from crewai_tools import FileReadTool
from faramesh.integrations import govern_crewai_tool

# One line!
tool = govern_crewai_tool(FileReadTool(), agent_id="researcher")

# Use in agent
from crewai import Agent

agent = Agent(
    role='Researcher',
    tools=[tool],
    verbose=True
)
```

**Full example:** [`examples/crewai/governed_agent.py`](examples/crewai/governed_agent.py)

## AutoGen

```bash
pip install pyautogen
```

```python
import autogen
from faramesh.integrations import govern_autogen_function

def my_function(url: str) -> str:
    import requests
    return requests.get(url).text

# One line!
governed_func = govern_autogen_function(
    my_function,
    agent_id="assistant",
    tool_name="http_get"
)

# Use in agent
agent = autogen.AssistantAgent(
    name="assistant",
    function_map={"http_get": governed_func}
)
```

**Full example:** [`examples/autogen/governed_agent.py`](examples/autogen/governed_agent.py)

## MCP

```bash
pip install mcp
```

```python
from faramesh.integrations import govern_mcp_tool

def my_mcp_tool(query: str) -> str:
    return f"Result: {query}"

# One line!
tool = govern_mcp_tool(my_mcp_tool, agent_id="my-agent")

# Use in MCP server
from mcp import Server
server = Server("my-server")
server.register_tool("my_tool", tool)
```

**Full example:** [`examples/mcp/governed_tool.py`](examples/mcp/governed_tool.py)

## Universal One-Liner

Auto-detect framework:

```python
from faramesh.integrations import govern

# Auto-detects framework
tool = govern(any_tool, agent_id="my-agent")
```

## What Happens Next?

1. **Tool calls are intercepted** before execution
2. **Submitted to Faramesh** for policy evaluation
3. **Require approval** if policy says so
4. **Execute only if allowed**
5. **View in UI** at `http://127.0.0.1:8000`

## Policy Configuration

Create `policies/default.yaml`:

```yaml
rules:
  - match:
      tool: "shell"
      op: "*"
    require_approval: true
    risk: "medium"

  - match:
      tool: "*"
      op: "*"
    deny: true
```

See [Policy Packs](policies/packs/) for ready-to-use policies.

## Next Steps

- [Complete Integration Guide](docs/INTEGRATIONS.md)
- [Govern Your Own Tool](docs/govern-your-own-tool.md)
- [Policy Packs](policies/packs/)
