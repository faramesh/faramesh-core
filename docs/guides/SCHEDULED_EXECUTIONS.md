# Scheduled tool executions — model, storage, and lifecycle

Faramesh persists scheduled tool calls so an agent can register an action to run at a future time, optionally re-evaluated against policy at the moment of execution. The store is the source of truth for the lifecycle; an executor (added in a follow-on PR) wakes up at the scheduled time and submits the call through the governance pipeline.

This document covers the storage layer and lifecycle. It does **not** cover the transport surface, the executor, or the CLI — those are wired in follow-on work.

## Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier of the form `sched_<hex>`, generated at creation. |
| `agent_id` | string | The agent that scheduled the call. |
| `tool` | string | Tool identifier (`<tool>/<operation>`). |
| `args` | string | Tool arguments as a JSON-encoded string; opaque to the schedule layer. |
| `policy` | string | Optional policy reference to evaluate against. |
| `reeval` | bool | When true, the executor re-runs policy evaluation at the scheduled time rather than locking in the create-time decision. |
| `scheduled_at` | timestamp | UTC time at which the call should run. |
| `created_at` | timestamp | UTC time at which the schedule was registered. |
| `status` | enum | One of `scheduled`, `pending_approval`, `approved`, `executed`, `failed`, `cancelled`. |
| `status_message` | string | Optional context, e.g. "policy deferred at exec time" or a tool error message. |
| `executed_at` | timestamp | UTC time at which the call ran (zero until executed). |
| `approved_at` | timestamp | UTC time of human approval (zero unless `pending_approval` was approved). |
| `approved_by` | string | Identifier of the approver. |

## Lifecycle

```
       create
         |
         v
  +---------------+    cancel   +-----------+
  |   scheduled   | ---------->| cancelled |
  +---------------+            +-----------+
         |
         | executor wakes; reeval=true and policy defers
         v
  +-------------------+   approve  +----------+
  | pending_approval  | ---------> | approved |
  +-------------------+            +----------+
         | reject / timeout                 |
         v                                  v
  +-----------+                       +----------+
  | cancelled |                       | executed |
  +-----------+                       |  failed  |
                                      +----------+
```

Transitions enforced by the `Service`:

- `Create` always inserts as `scheduled`.
- `Cancel` is permitted from `scheduled`, `pending_approval`, or `approved`; rejected from terminal states.
- `Approve` is permitted only from `pending_approval`.
- `MarkPendingApproval` and `MarkExecuted` are intended for the executor (added in the follow-on PR) and are likewise gated.

## Time format

`Service.Create` accepts two `at` formats:

- **RFC3339** — `2026-12-31T23:59:00Z` for an absolute moment.
- **Relative** — `+30m`, `+2h`, `+1d`, `+2d3h` for an offset from now. The `d` (days) extension is honoured by `parseRelativeDuration` in addition to the units supported by `time.ParseDuration`.

An empty `at` schedules for "now" (immediate), useful as a deferred-policy hook with `reeval=true`.

## Storage

Two `Store` implementations are provided.

### `MemoryStore`

In-process map keyed by ID, guarded by `sync.RWMutex`. Suitable for tests and ephemeral daemons. **Not** an evidence-trail store — schedules are lost on restart.

### `SQLiteStore`

Backed by `modernc.org/sqlite` (pure-Go, no CGO). Default on-disk path is `${data_dir}/schedules.db`, sibling to `delegations.db` and `session_daily_costs.db`.

**Schema (`schedule/1.0`)**

```sql
CREATE TABLE scheduled_executions (
  id              TEXT PRIMARY KEY,
  schema_version  TEXT NOT NULL DEFAULT 'schedule/1.0',
  agent_id        TEXT NOT NULL,
  tool            TEXT NOT NULL,
  args            TEXT NOT NULL DEFAULT '',
  policy          TEXT NOT NULL DEFAULT '',
  reeval          INTEGER NOT NULL DEFAULT 0,
  scheduled_at    INTEGER NOT NULL,    -- UTC unix seconds
  created_at      INTEGER NOT NULL,    -- UTC unix seconds
  status          TEXT NOT NULL,
  status_message  TEXT NOT NULL DEFAULT '',
  executed_at     INTEGER NOT NULL DEFAULT 0,
  approved_at     INTEGER NOT NULL DEFAULT 0,
  approved_by     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_scheduled_agent        ON scheduled_executions(agent_id);
CREATE INDEX idx_scheduled_status       ON scheduled_executions(status);
CREATE INDEX idx_scheduled_scheduled_at ON scheduled_executions(scheduled_at);
CREATE INDEX idx_scheduled_executed_at  ON scheduled_executions(executed_at);
```

Pragmas (`journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `foreign_keys=ON`) and the single-writer connection pool match the existing DPR store. Schema is created idempotently in `migrateSchedule` at construction; the `schema_version` column is reserved for future additive migrations.

## Operational notes

- **Backup** `schedules.db` alongside the DPR store and the delegation store. Loss of the file means in-flight schedules and their approval state are gone, but enforcement is unaffected.
- **Multi-instance deployments** must share the database (or use a future networked backend) so that any daemon can see schedules another created.
- **Time zones** — every timestamp is stored as UTC unix seconds. RFC3339 inputs with offsets are converted to UTC at parse time.

## See also

- `cmd/faramesh/schedule.go` — the CLI surface backed by this package (transport added in the follow-on PR).
- `docs/guides/DELEGATION_GRANTS.md` — sibling persistence layer using the same SQLite + migration pattern.
