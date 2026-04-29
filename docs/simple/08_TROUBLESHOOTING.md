# Troubleshooting (Simple)

## Daemon will not start

Check policy first:

```bash
faramesh policy validate policy.yaml
```

If valid, run with debug logs:

```bash
faramesh up --policy policy.yaml
faramesh serve --policy policy.yaml --log-level debug
```

## `audit tail` cannot connect

Usually runtime is not running.

```bash
faramesh status
faramesh up --policy policy.yaml
faramesh audit tail
```

Advanced operator case: if you intentionally run multiple runtimes with custom sockets,
target the intended runtime explicitly.

## Lots of DEFERs, nothing executes

This usually means policy is intentionally requiring manual approval.

Approve manually:

```bash
faramesh approvals
faramesh approvals approve <approval-id>
```

## Denies are hard to understand

Use explain:

```bash
faramesh explain <action-id>
faramesh explain approval <approval-id>
faramesh explain agent <agent-id>
```

## Chain verify fails

Run:

```bash
faramesh audit verify
```

Advanced operator case for explicit WAL path:

```bash
faramesh audit verify /path/to/faramesh.wal
```

If violations appear, treat as data integrity incident.

## MCP gateway returns 502

This usually means `--mcp-target` is down/unreachable.

Test target health directly and restart `faramesh serve` with correct target URL.

## Corpus harness fails with "vault CLI is required"

Some real-stack harnesses need local Vault CLI. In environments without Vault (for example minimal CI runners), framework corpus wrappers should fall back to deterministic governed smoke harnesses.

If you run real-stack locally, install Vault CLI first.

## Build fails with missing `github.com/faramesh/faramesh-core/api/v1`

This means code is still importing private control-plane contract packages. OSS runtime code should depend on the local daemon adapter contract in `internal/adapter/daemon`, not private API folders.

## eBPF not available on macOS

Expected behavior.

- eBPF path requires Linux kernel support.
- On macOS, use SDK/proxy/MCP adapters.

## Auth login fails

Check URL and connectivity:

```bash
faramesh auth login --horizon-url https://your-horizon-url
faramesh auth status
```
