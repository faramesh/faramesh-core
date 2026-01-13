# LangChain Integration Example

This example demonstrates how to use FaraCore with LangChain agents.

## Setup

1. Install dependencies:
```bash
pip install langchain openai
```

2. Start FaraCore server:
```bash
faracore serve
```

3. Run the example:
```bash
python examples/langchain/governed_agent.py
```

## How It Works

The `GovernedTool` wrapper:
- Intercepts tool calls before execution
- Submits them to FaraCore for policy evaluation
- Waits for approval if required
- Executes the tool only if allowed/approved
- Reports results back to FaraCore

## Usage

```python
from langchain.tools import ShellTool
from faracore.sdk.client import ExecutionGovernorClient
from faracore.integrations.langchain.governed_tool import GovernedTool

# Create FaraCore client
client = ExecutionGovernorClient("http://127.0.0.1:8000")

# Wrap LangChain tool
shell_tool = ShellTool()
governed = GovernedTool(
    tool=shell_tool,
    client=client,
    agent_id="my-agent"
)

# Use in agent or directly
result = governed.run("ls -la")
```

## Integration with Agents

```python
from langchain.agents import initialize_agent, AgentType

# Wrap all tools
governed_tools = [
    GovernedTool(tool=t, client=client, agent_id="agent-1")
    for t in [shell_tool, http_tool]
]

# Create agent with governed tools
agent = initialize_agent(
    tools=governed_tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
)
```
