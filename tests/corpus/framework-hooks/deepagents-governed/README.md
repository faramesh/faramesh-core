# deepagents-governed

Purpose:

- Proves Faramesh patches DeepAgents `create_deep_agent` and governs both direct tool calls and execute-layer tool dispatch.
- Promotes DeepAgents coverage from adapter/unit-only truth into a real runtime harness row.

Coverage:

- patch verification for `create_deep_agent`
- direct PERMIT, DENY, and DEFER probes
- DeepAgents execute-layer permit and deny probes
- client-visible approval/resume continuity for deferred `payments_refund`
- DPR persistence for observed permit/deny/defer paths, including the resumed `PERMIT` with `approval_envelope`, plus `audit verify` and WAL replay parity
- optional live OpenRouter call when `OPENROUTER_API_KEY` is present

Harness:

- Delegates to `tests/deepagents_real_stack.sh`

Known limitations:

- Live OpenRouter execution is optional and skipped when `OPENROUTER_API_KEY` is absent
