# DPR signing keys — production operations

Historical note: this file started as an HMAC-only runbook. Faramesh now uses
Ed25519 for DPR record signatures and keeps HMAC for approval-envelope
integrity/compatibility workflows.

## Default behavior

- DPR Ed25519 keypair is persisted under runtime data directory:
	- `faramesh.ed25519.key` (private, mode `0600`)
	- `faramesh.ed25519.pub` (public)
	- `faramesh.ed25519.meta.json` (key metadata)
- HMAC key is persisted at `faramesh.hmac.key` (mode `0600`) unless supplied explicitly via `--dpr-hmac-key`.
- `--dpr-hmac-key` should come from secret management, not shell history.

## Operational requirements

1. **Back up** Ed25519 private key and HMAC key with WAL/DB backups.
2. **Rotate** keys intentionally and keep old public/HMAC material if you need to verify historical evidence.
3. **Multi-instance** deployments must use a consistent key-management strategy across nodes:
	- shared verification trust for Ed25519 public keys,
	- shared HMAC secret for approval-envelope compatibility paths.

## Migration / re-sign workflow

Use `compliance resign` to backfill Ed25519 signatures for historical records.

Dry-run:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data
```

Apply:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data --apply
```

Scope controls:

```bash
faramesh compliance resign --data-dir ~/.faramesh/runtime/data --limit 5000 --only-missing
```

The command replays validated WAL records, updates signature fields in DPR store,
and verifies chain integrity after apply.

## Standing grant admin token (related)

Standing grant APIs (`standing_grant_add`, `standing_grant_revoke`, `standing_grant_list`) require an `admin_token` in the JSON payload matching the daemon’s configured secret:

- `--standing-admin-token` or `FARAMESH_STANDING_ADMIN_TOKEN`, or
- If those are unset, the daemon falls back to `--policy-admin-token` / `FARAMESH_POLICY_ADMIN_TOKEN`.

Without any of these configured, standing grant **SDK endpoints are disabled** (fail closed). Unix socket permissions are **not** sufficient for administrative grant operations.

## Related commands

- `faramesh key export dpr` — print DPR public key (use `--verbose` for metadata).
- `faramesh audit verify` — WAL chain replay vs SQLite spot checks.
- `faramesh audit wal-inspect` — frame version distribution for migration planning.
- `faramesh audit show <action-id>` — per-record cryptographic status (`record_hash_valid`, `signature_valid`).
