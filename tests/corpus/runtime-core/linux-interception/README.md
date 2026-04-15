# Linux `faramesh run` interception matrix

Wraps `tests/linux_interception_matrix_harness.sh`: builds `cmd/faramesh`, runs `faramesh run` under profile matrix, and asserts the enforcement report contains expected layers (seccomp, Landlock, broker, etc.).

- **Linux:** full checks (CI `ubuntu-latest` runs this via `corpus-harness`).
- **macOS / Windows:** harness exits **0** immediately (“skipped”); use CI or a Linux box for real signal.

**WIP** in the corpus contract: integration of native enforcement stacks, not agent `hook_truth` / WAL tier-A.
