# langgraph-single-agent

This corpus entry exercises the existing LangGraph real-stack harness.

Why it exists:

- Proves the LangGraph interception hooks remain active
- Verifies permit, deny, defer, credential-brokered behavior, audit verification, and WAL replay parity through the LangGraph tool execution path
- Acts as the first compatibility-lab row for the LangGraph family

Current harness:

- Delegates to `tests/langgraph_single_agent_real_stack.sh`

Known limitations:

- This is single-agent coverage, not the full multi-agent LangGraph corpus target yet
