# DPR HMAC key — production operations

The daemon signs Decision Persistence Record (DPR) payloads with an HMAC key so approvals and audit evidence are tamper-evident. How you manage that key determines whether signatures survive restarts and who can rely on them.

## Default behavior

- If you **do not** pass `--dpr-hmac-key`, the daemon generates a random key and **persists** it under the data directory as `faramesh.hmac.key` (mode `0600`) so signatures remain stable across process restarts on the same host.
- If you **do** pass `--dpr-hmac-key`, that exact secret is used; store it in a secrets manager or sealed deployment config, not in shell history.

## Operational requirements

1. **Back up** `faramesh.hmac.key` with the same care as the WAL and SQLite DPR store. Losing the key does not stop enforcement, but it breaks verification of historical signatures that were produced with the old key.
2. **Rotate** by deploying a new key file (or new `--dpr-hmac-key` value) during a maintenance window; expect a clean break for signature continuity on old records unless you keep old keys for verification tooling.
3. **Multi-instance** deployments must share the **same** HMAC key if each instance must verify approvals or envelopes produced by another (for example Redis-backed defer with cross-node approval validation).

## Standing grant admin token (related)

Standing grant APIs (`standing_grant_add`, `standing_grant_revoke`, `standing_grant_list`) require an `admin_token` in the JSON payload matching the daemon’s configured secret:

- `--standing-admin-token` or `FARAMESH_STANDING_ADMIN_TOKEN`, or
- If those are unset, the daemon falls back to `--policy-admin-token` / `FARAMESH_POLICY_ADMIN_TOKEN`.

Without any of these configured, standing grant **SDK endpoints are disabled** (fail closed). Unix socket permissions are **not** sufficient for administrative grant operations.

## Related commands

- `faramesh audit verify` — WAL chain replay vs SQLite spot checks.
- `faramesh audit wal-inspect` — frame version distribution for migration planning.
