# langchain-simple

This corpus entry exercises the existing LangChain real-stack harness.

Why it exists:

- Proves the LangChain autopatch path still intercepts tool calls
- Verifies permit, deny, defer, credential-brokered behavior, audit verification, and WAL replay parity in one flow
- Provides a stable compatibility row for the release coverage matrix

Current harness:

- Delegates to `tests/langchain_single_agent_real_stack.sh`

Known limitations:

- The shared demo agent lives outside this entry and should be localized in a later corpus hardening pass
