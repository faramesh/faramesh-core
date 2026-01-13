"""
Example: LangChain agent with FaraCore governance

This example shows how to use FaraCore to govern LangChain tool calls.
"""

from langchain.agents import initialize_agent, AgentType
from langchain.tools import ShellTool
from langchain.llms import OpenAI  # or any LLM

from faracore.sdk.client import ExecutionGovernorClient
from faracore.integrations.langchain.governed_tool import GovernedTool


def main():
    # Initialize FaraCore client
    client = ExecutionGovernorClient("http://127.0.0.1:8000")
    
    # Create a shell tool
    shell_tool = ShellTool()
    
    # Wrap it with FaraCore governance
    governed_shell = GovernedTool(
        tool=shell_tool,
        client=client,
        agent_id="langchain-demo",
    )
    
    # Initialize LLM (replace with your API key)
    # llm = OpenAI(temperature=0)
    
    # Create agent with governed tool
    # agent = initialize_agent(
    #     tools=[governed_shell],
    #     llm=llm,
    #     agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    #     verbose=True,
    # )
    
    # Example: Direct tool usage
    print("Testing governed shell tool...")
    try:
        result = governed_shell.run("echo 'Hello from FaraCore'")
        print(f"Result: {result}")
    except PermissionError as e:
        print(f"Action denied: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
