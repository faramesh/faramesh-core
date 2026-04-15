# Defer timeout / resume stress (G3 harness)

Wraps `tests/defer_timeout_resume_stress_harness.sh`: `internal/core/defer` and `internal/adapter/daemon` races around timeouts, late approvals/denials, and triage ordering.

**WIP** in the corpus contract: tracks runtime defer correctness separately from agent `hook_truth` rows.
