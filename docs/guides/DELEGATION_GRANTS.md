# Delegation grants — model, storage, and lifecycle

Faramesh persists agent-to-agent delegation grants so a supervisor agent can authorise a sub-agent to act on its behalf within a bounded scope, time window, and chain depth. Tokens are signed offline and the store is the source of truth for revocation and chain reconstruction.

This document covers the storage layer and grant lifecycle. It does **not** cover the transport surface or CLI — those are wired in follow-on work.

## Grant fields

| Field | Type | Description |
|---|---|---|
| `token` | string | Opaque identifier of the form `del_<b64payload>.<b64hmac>`. Self-describing and verifiable offline. |
| `from_agent` | string | The agent issuing the delegation (the supervisor). |
| `to_agent` | string | The agent receiving the delegation (the sub-agent). |
| `scope` | string | Tool pattern the delegate is permitted to invoke. Supports trailing-`*` glob. |
| `ceiling` | string | Optional spending or action ceiling carried alongside the grant for downstream enforcement. |
| `issued_at` | timestamp | UTC issue time. |
| `expires_at` | timestamp | UTC expiry. Grants beyond this are rejected by `Verify`. |
| `chain_depth` | int | 1 for root grants; `parent.chain_depth + 1` when `from_agent` already holds an inbound grant. Capped by `delegate.DefaultMaxDepth` (5) or the configured override. |
| `active` | bool | False after revocation. Chain walks and verification both honour this. |

## Tokens

Tokens are produced by `delegate.Issue(grant, key)` and verified by `delegate.Parse(token, key)`.

- **Format**: `del_<base64url(payload)>.<base64url(HMAC-SHA256(payload, key))>`
- **Payload**: canonical JSON of the signed fields. Field order is fixed via Go struct declaration order, so the wire form is stable across processes.
- **Signing key**: derived from the daemon's existing DPR HMAC key with a fixed domain separator (`HMAC-SHA256(dprKey, "faramesh.delegate.v1")`). No second persisted secret is required; rotating the DPR key invalidates delegation tokens by the same mechanism.
- **Tamper resistance**: any byte change to the payload or signature segment causes `Parse` to return `ErrInvalidToken` before the store is ever consulted.

## Grant lifecycle

### Issuance

`Service.Grant(req)` performs:

1. **Input validation** — `from_agent` and `to_agent` are required and must differ; `ttl` must parse as a positive `time.Duration`.
2. **Parent lookup** — the most-recent active inbound grant on `from_agent` is treated as the parent for chain depth and scope-subset checks.
3. **Depth enforcement** — `parent.chain_depth + 1` must not exceed the configured maximum. `delegate.DefaultMaxDepth` (5) is the conservative default.
4. **Scope-subset enforcement** — for chained grants, the new scope must be a subset of the parent's scope (trailing-`*` glob semantics, multiple scopes allowed via space/comma separation).
5. **Issuance** — issue and persist the grant atomically. The token is the primary key.

### Verification

`Service.Verify(token)` checks, in order:

1. **Signature** — `Parse(token)` rejects tampered tokens before any store hit.
2. **Presence** — the token must be in the store. (Reject self-issued tokens that were never persisted.)
3. **Active** — revocation flips the `active` column; verification fails closed.
4. **Expiry** — current time must be before `expires_at`.

A successful `Verify` returns `{valid: true, scope, expires_at, chain_depth}` for downstream use.

### Revocation

`Service.Revoke(from, to)` deactivates **all** active grants from `from_agent` to `to_agent`. Idempotent: subsequent calls return zero rows affected.

### Chain reconstruction

`Service.Chain(agent_id)` walks inbound grants from the leaf back to the root, returning links ordered root-to-leaf. Cycle detection is by visited-set on the from-agent, so corrupt or adversarial state cannot induce an infinite walk.

## Storage

Two `Store` implementations are provided.

### `MemoryStore`

In-process map keyed by token, guarded by a `sync.RWMutex`. Suitable for tests and ephemeral daemons. **Not** an evidence-trail store — grants are lost on restart.

### `SQLiteStore`

Backed by `modernc.org/sqlite` (pure-Go, no CGO). Default on-disk path is `${data_dir}/delegations.db`, sibling to `faramesh.hmac.key` and the daily-cost store.

**Schema (`delegate/1.0`)**

```sql
CREATE TABLE delegate_grants (
  token           TEXT PRIMARY KEY,
  schema_version  TEXT NOT NULL DEFAULT 'delegate/1.0',
  from_agent      TEXT NOT NULL,
  to_agent        TEXT NOT NULL,
  scope           TEXT NOT NULL DEFAULT '*',
  ceiling         TEXT NOT NULL DEFAULT '',
  issued_at       INTEGER NOT NULL,  -- UTC unix seconds
  expires_at      INTEGER NOT NULL,  -- UTC unix seconds
  chain_depth     INTEGER NOT NULL DEFAULT 1,
  active          INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_delegate_grants_from        ON delegate_grants(from_agent);
CREATE INDEX idx_delegate_grants_to          ON delegate_grants(to_agent);
CREATE INDEX idx_delegate_grants_active_to   ON delegate_grants(active, to_agent);
```

**Pragmas** match the existing DPR store conventions: `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `foreign_keys=ON`. `MaxOpenConns=1` keeps SQLite single-writer.

**Migrations**

The schema is created idempotently in `migrateDelegate(db)` at construction. The `schema_version` column is reserved for forward-compatible additive migrations; rows from the v1 schema default to `delegate/1.0`.

## Operational notes

- **Backup** `delegations.db` with the same care as the WAL and SQLite DPR store. Loss of the file does not stop enforcement, but in-flight delegations and audit history are gone.
- **Rotate the DPR HMAC key** with awareness that tokens issued under the prior key will fail `Verify`. If chains must survive rotation, plan a maintenance window.
- **Multi-instance deployments** should share the SQLite database (or replace `SQLiteStore` with a future networked backend) so grants visible to one daemon are visible to all.

## CLI usage

The `faramesh delegate` subcommand talks to the daemon over the authenticated SDK socket. All operations require an admin token, sourced in this order:

1. `--admin-token <secret>` flag.
2. `FARAMESH_STANDING_ADMIN_TOKEN` environment variable.
3. `FARAMESH_POLICY_ADMIN_TOKEN` environment variable.

The daemon must have a matching token configured (see [`DPR_HMAC_KEY.md`](DPR_HMAC_KEY.md) — the same admin-token guidance applies). Without one, every `faramesh delegate` call fails closed with `control_admin_unconfigured`.

```bash
# Grant a 1-hour delegation from a supervisor agent to a worker agent
# scoped to stripe/* tools.
export FARAMESH_STANDING_ADMIN_TOKEN=<secret>
faramesh delegate grant supervisor worker --scope "stripe/*" --ttl 1h

# Inspect / verify the resulting token.
faramesh delegate inspect del_<...>
faramesh delegate verify  del_<...>

# List delegations involving a given agent.
faramesh delegate list worker

# Walk the chain from the leaf agent back to the root.
faramesh delegate chain worker

# Revoke. Idempotent — re-running returns "no active delegations found".
faramesh delegate revoke supervisor worker
```

If the SDK socket is unreachable and `--http-fallback --addr <daemon-http>` is set, the CLI falls back to the equivalent `/api/v1/delegate/*` HTTP route. By default the SDK socket is the only path.

## See also

- [`DPR_HMAC_KEY.md`](DPR_HMAC_KEY.md) — the parent key used to derive the delegation signing key.
- `internal/core/principal/delegation.go` — the runtime `DelegationChain` type that policy evaluation consumes. Persistent grants in this package are the source of truth; that runtime type is the projection presented to the engine on each tool call.
