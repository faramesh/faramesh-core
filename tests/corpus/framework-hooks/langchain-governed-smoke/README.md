# langchain-governed-smoke

This corpus entry exercises the lightweight LangChain governed socket harness.

Why it exists:

- Provides a CI-friendly LangChain corpus row that does not depend on Vault
- Verifies framework autopatch, durable permit evidence, audit verification, and WAL replay parity
- Gives the release gate one truthful framework-hook execution row on every run

Current harness:

- Delegates to `tests/langchain_single_agent_governed.sh`

Known limitations:

- This is a smoke row, not the full higher-stakes LangChain real-stack flow
- It only asserts a permitted governed tool call, not deny/defer or brokered credential paths
