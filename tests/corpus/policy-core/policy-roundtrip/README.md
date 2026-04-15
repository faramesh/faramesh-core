# Policy YAML round-trip (CLI harness)

Exercises `faramesh policy validate`, strict-lossless decompile, and `faramesh policy test` over generated fixtures (`tests/policy_roundtrip_harness.sh`).

Corpus status is **wip**: this row tracks compiler/CLI truth separately from agent **hook_truth** / tier **A** replay rows. Upgrade to **passing** only after the contract script accepts a dedicated non-agent profile or the harness gains WAL parity assertions aligned with `AGENT_CORPUS_SPEC.md`.
