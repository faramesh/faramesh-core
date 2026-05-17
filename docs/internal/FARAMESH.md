# Faramesh — authoritative specification

**Status:** Phase 0a (specification and contracts). Implementation phases 1–12 track below.  
**Scope:** `faramesh-core/`, `fpl-lang/`, adapter SDKs. Hosted SaaS: [`FARAMESH_CLOUD_PLATFORM_EXPANSION_PLAN.md`](../../../docs/internal/FARAMESH_CLOUD_PLATFORM_EXPANSION_PLAN.md) (separate product).  
**Public docs:** `faramesh-docs/` is rewritten only after phases 1–12 land; until then this file is the operator and implementer source of truth.

This document supersedes all prior internal planning files (`FARAMESH_PART_A_*`, `FARAMESH_PART_B_*`, `FARAMESH_UNIFIED_IMPLEMENTATION_PLAN.md`, `FARAMESH_PHASE_REMEDIATION_*`). Those files are removed from the repository.

---

## 1. What Faramesh is

Faramesh is the production runtime for AI agents. It governs tool calls **before** they execute: every call is canonicalized into a Canonical Action Request (CAR), evaluated by a deterministic policy engine, and recorded as a cryptographically linked Decision Provenance Record (DPR) in a write-ahead log (WAL) before any permit is issued.

Faramesh is **not** Vault, Okta, Datadog, or a SIEM. It is the agent-aware orchestration layer in front of those systems: it brokers credentials, verifies workload identity, enforces policy, and produces a correlated evidence trail.

**Governance as Code (GaC):** The pivot from ~60 `faramesh serve` flags to one declarative file per stack — `governance.fms` (FPL, YAML, or JSON). The enforcement core (AAB, CAR, DPR/WAL, fail-closed) is unchanged.

---

## 2. Stack

A **stack** is one directory that contains exactly one governance config file and one Faramesh daemon instance.

- One stack → one compiled config → one WAL → one set of providers.
- Multiple stacks on one machine are independent (separate daemons, sockets, WAL directories).
- Stack boundary = organizational ownership and deployment atomicity, not machine count.

**Config file names (syntax detection):**

| File | Syntax |
|------|--------|
| `governance.fms` | FPL if first non-comment line is not `---` and not `{` |
| `governance.fms` | YAML if first non-comment line is `---` |
| `governance.fms` | JSON if first non-comment character is `{` |
| `governance.fms.yaml` | YAML |
| `governance.fms.json` | JSON |

Mixed syntax across imported files is rejected at compile time with an error naming both files and detected syntaxes.

**Agent naming in `faramesh init`:** `agent "<stack-slug>-agent"` where `stack-slug` is the stack directory basename, lowercased, with runs of non `[a-z0-9-]` replaced by `-`, trimmed of leading/trailing `-`. Example: directory `Payment-Service` → agent `payment-service-agent`.

---

## 3. Multi-syntax equivalence

All three syntaxes compile to the same internal AST (Phase 1). The compiler operates on the AST only.

| Concept | FPL | YAML / JSON |
|---------|-----|-------------|
| Environment variable | `env("VAR")` | `${VAR}` |
| Unconditional deny | `deny! tool/pattern` | `deny_unconditional: "tool/pattern"` |
| Provider reference in credential | `backend = vault` | `backend: vault` |

Inline secret strings in provider config are a **compile error**. Use `env()` / `${VAR}` only.

---

## 4. Top-level blocks

```ebnf
Document = { ImportDecl | RuntimeBlock | ProviderBlock | IdentityBlock
           | TrustBlock | AgentBlock | Comment } ;
```

- **`runtime { }`** — daemon mode, WAL, persistence, observability, TLS, defer backend, cold-start, admin tokens, optional `immutable_config`, Horizon sync.
- **`provider "name" { }`** — `type`, optional `source` (registry URL or local path to sidecar binary), plus opaque key-value config passed to `Init`.
- **`identity "name" { }`** — SPIFFE, Okta, Teleport, Auth0, OIDC fields.
- **`trust { }`** — agent-to-agent delegation ceilings and inbound A2A trust.
- **`agent "name" { }`** — rules, budget, credentials, rate_limit, redact, egress, model_policy, session, spawn, completion_gate, enforcement, alert, phases, delegate.
- **`import "registry.faramesh.dev/.../name@version"`** — mandatory version pin; `@latest` is invalid.

---

## 5. Agent body extensions (summary)

Existing FPL inside `agent { }` (rules, budget, phases, credentials, delegation, ambient) is preserved.

| Block | Purpose |
|-------|---------|
| `rate_limit <pattern>: <N> per <window>` | Frequency cap; WAL `RATE_UPDATE`; effect `rate_exceeded` |
| `redact <pattern> args: ["json.path", ...]` | Keyed HMAC before WAL; failure → DENY `redaction_failure` |
| `egress { allow [...], deny [...] }` | Default deny-all external egress if block omitted |
| `model_policy { allow [...] }` | Approved model API endpoints (`model_call` CAR) |
| `session { max_duration, idle_timeout }` | Hard session limits |
| `spawn { max_concurrent, allowed_types [...] }` | Dynamic sub-agent creation |
| `completion_gate { require ... }` | Evaluated at Stop lifecycle (see §12) |
| `enforcement { seccomp, landlock, ebpf, ebpf_lsm, firecracker, mcp_proxy_port, http_proxy_port, allowed_paths }` | OS containment (see §18) |
| `alert { on = "<expr>", notify = "..." }` | Deterministic predicate on DPR stream; no LLM |

`credential "name" { backend = <provider-name>, path, ttl, scope }` — `backend` must resolve to a declared `provider` block.

`budget` — see §13 for `warn_at`.

---

## 6. ProviderService protocol

Proto: [`proto/provider/v1/provider.proto`](../../proto/provider/v1/provider.proto).

| Capability | RPC | When called |
|------------|-----|-------------|
| (always) | `Init`, `HealthCheck` | Startup; periodic health |
| SECRETS | `GetSecret` | Credential issuance |
| IDENTITY | `VerifyIdentity` | Before credentials when `workload_id` set |
| KMS | `Sign` | DPR signing (production standard from Phase 7) |
| AUDIT_SINK | `SinkDPR` | Each DPR write (external SIEM) |
| COST | `CostEstimate` | When policy uses `estimated_cost` (Phase 11) |

Third-party providers: `source` in provider block → download signed binary → Unix socket gRPC. Built-in providers implement the same interface in-process (no daemon branches per vendor).

`faramesh check` calls `Init` with `dry_run = true` for each provider and surfaces validation errors at the provider block location.

---

## 7. CAR action types

`CanonicalActionRequest.action_type` (default `tool_call`):

| Type | Use |
|------|-----|
| `tool_call` | Existing tool dispatch |
| `agent_delegation` | Outbound A2A task |
| `model_call` | Foundation model API |
| `session_spawn` | Dynamic sub-agent |
| `inbound_delegation` | Inbound A2A task |
| `completion_event` | MCP async Task completion (Nov 2025 spec) |

DPR schema `dpr/2.0` adds `action_type`, `lamport_seq`, `kms_signature`, `kms_key_ref`, optional `reasoning_summary` (see §14).

---

## 8. Daemon lifecycle

```
STARTING → INITIALIZING → READY
                ↓ (cold_start_deny_window exceeded)
               HALT
READY → DRAINING → INITIALIZING  (provider/identity change on apply)
```

During `STARTING` and `INITIALIZING`, all governance requests return structured denial `DAEMON_NOT_READY` (§11). No permits until `READY`.

Budget and rate state: WAL frames `BUDGET_UPDATE`, `RATE_UPDATE` replayed before `READY`.

---

## 9. CLI surface (target)

**Core:** `init`, `check`, `plan`, `apply`, `status`, `destroy`  
**Utilities:** `test`, `explain`, `rollback`  
**Groups:** `approvals`, `audit`, `credential`, `agent`  
**Dev:** `dev` (Phase 8)

`apply` always runs `check` first; cannot be skipped. `apply --stop` stops the daemon. Legacy commands (`serve`, `discover`, `coverage`, `gaps`, …) are removed in Phase 2.

**Three flows:**

1. First setup: `init` → edit `governance.fms` → `check` → `plan` → `apply` → `status`
2. Change: edit → `check` → `plan` → PR review → `apply`
3. Monitor: `status` → `approvals list` → `audit tail` → `explain <id>`

---

## 10. `faramesh init` — complete specification

### 10.1 Behavior

- Runs **once per stack**; never starts the daemon.
- Writes `governance.fms` in the stack directory (or `governance.fms.yaml` / `governance.fms.json` when flags request it — Phase 2).
- If `governance.fms` (or `.yaml`/`.json` variant for that run) already exists: print error below, **exit 1**, do not overwrite.
- Network: one HTTPS fetch for framework profile metadata when writing the `import` line; **no network** with `--offline`.

### 10.2 Flags

| Flag | Effect |
|------|--------|
| `--offline` | Omit `import` line; no registry HTTP |
| `--non-interactive` | No prompts; if framework unknown, write file with `# TODO: set framework import` and exit 0 |
| `--dir=PATH` | Stack directory (default: current working directory) |

Phase 2 adds `--yaml`, `--json` for output filename/syntax.

### 10.3 Framework detection (precedence)

1. **Python:** `pyproject.toml`, `requirements.txt`, `requirements*.txt` — package names:
   - `langgraph` or `langchain` → `langgraph`
   - `crewai` → `crewai`
   - `autogen` or `ag2` → `ag2`
   - `google-adk` or `google.adk` → `google-adk`
   - `openai-agents` or package `agents` (OpenAI Agents SDK) → `openai-agents`
   - `anthropic` plus agent/tool patterns in tree → `anthropic-sdk`
   - `strands-agents` → `strands`
   - `boto3` + Bedrock action-group patterns in `.json`/`.yaml` → `bedrock`
   - `fastmcp` or `mcp` → `mcp`
2. **Node:** `package.json` dependencies for the same logical frameworks (npm package names as published).
3. **Root files:** `deepagents.toml`, `agents.toml`, or `AGENTS.md` → `deep-agents`
4. **Ambiguous** (multiple matches): print detected list; one interactive selection.
5. **Undetected:** prompt “Which framework are you using?” with numbered list of: `langgraph`, `langchain`, `crewai`, `ag2`, `google-adk`, `openai-agents`, `anthropic-sdk`, `strands`, `bedrock`, `mcp`, `deep-agents`, `other / I'll specify manually`.

Framework profile import pin for generated file: `registry.faramesh.dev/frameworks/<framework>@1.0.0` (never `@latest`).

### 10.4 Tool discovery (per framework)

Record per tool: **name**, **file path**, **line number**, **registration kind**.

| Framework | Patterns |
|-----------|----------|
| langgraph / langchain | `@tool`, `Tool(...)`, `StructuredTool(...)`, `tool(...)`, `tools=[...]` |
| crewai | `@tool`, `Tool(...)`, `BaseTool` subclasses |
| ag2 | `register_function(...)`, `@register_for_execution`, `@register_for_llm` |
| google-adk | `@tool`, `FunctionTool(...)`, `tools=[...]` |
| openai-agents | `@function_tool`, `FunctionTool(...)`, `tools=[...]` |
| mcp | `server.tool()`, `@mcp.tool()`, `add_tool(...)` |
| deep-agents | `skills/**/SKILL.md`, `mcp.json` tool entries |
| bedrock | action group definitions in `.json` / `.yaml` |

Discovered tools become `defer <tool-id>` lines in `rules { }` (tool-id = discovered name, normalized to FPL tool pattern rules).

### 10.5 Substitution rules (generated file)

Implementers substitute these tokens when writing `governance.fms`:

| Token | Source |
|-------|--------|
| `{{STACK_NAME}}` | Stack directory basename |
| `{{FRAMEWORK}}` | Detected or selected framework id |
| `{{GENERATED_AT}}` | UTC ISO 8601, e.g. `2026-05-16T17:30:00Z` |
| `{{AGENT_NAME}}` | `<stack-slug>-agent` per §2 |
| `{{IMPORT_LINE}}` | `import "registry.faramesh.dev/frameworks/{{FRAMEWORK}}@1.0.0"` or empty line if `--offline` |
| `{{TOOL_COMMENT_LINES}}` | One line per tool: `#   <name> — <path>:<line> (<kind>)` |
| `{{TOOL_DEFER_LINES}}` | One line per tool: `    defer <name>` |
| `{{ENFORCEMENT_BLOCK}}` | If framework is `mcp`, insert §10.6 MCP block; else empty |
| `{{RULES_BODY}}` | Either defer lines, or no-tools comment block |

### 10.6 MCP `enforcement` block (inserted only when `{{FRAMEWORK}}` is `mcp`)

```fpl
  enforcement {
    mcp_proxy_port = 8081
  }
```

### 10.7 File template (bytes written — SDK / default frameworks)

When `{{TOOL_DEFER_LINES}}` is non-empty:

```fpl
# governance.fms
# Generated by faramesh init
# Stack: {{STACK_NAME}}
# Framework: {{FRAMEWORK}}
# Generated: {{GENERATED_AT}}
#
# faramesh dev    — run governance locally, no external infrastructure
# faramesh apply  — start enforcement
# Docs: https://docs.faramesh.dev

{{IMPORT_LINE}}

runtime {
  mode    = "enforce"
  wal_dir = "./faramesh-wal"
  backend = "sqlite"
}

# No provider declared — faramesh dev provides built-in stubs.
# For production, add a provider block. See: https://docs.faramesh.dev/providers

agent "{{AGENT_NAME}}" {
  # Tools discovered in this project:
{{TOOL_COMMENT_LINES}}

  rules {
    # All discovered tools defer by default. Review: faramesh approvals list
    # Change to permit after review: permit <tool-name>
{{TOOL_DEFER_LINES}}
  }

  budget daily {
    max       = $10.00
    warn_at   = 0.8
    on_exceed = deny
  }

  egress {
    # No external egress permitted by default.
    # allow = ["api.example.com"]
  }
{{ENFORCEMENT_BLOCK}}
}
```

When no tools discovered, replace `{{TOOL_COMMENT_LINES}}`, `rules { ... }` inner content with:

```fpl
  # No tools were discovered in this project.
  # Add rules when you register tools. See: https://docs.faramesh.dev/fpl

  rules {
    # Example: defer my_tool
  }
```

`{{ENFORCEMENT_BLOCK}}` still appended inside `agent` when framework is `mcp`.

`--non-interactive` and framework unknown: write the template with `{{FRAMEWORK}}` = `unknown`, `{{IMPORT_LINE}}` = `# TODO: import "registry.faramesh.dev/frameworks/<framework>@1.0.0"`, empty tool sections.

### 10.8 Resolved example (reference implementation must match)

Directory: `my-app`, framework: `langgraph`, tools: `search_docs` (./agent.py:12, @tool), `send_email` (./agent.py:20, @tool).

**File written (`governance.fms`):**

```fpl
# governance.fms
# Generated by faramesh init
# Stack: my-app
# Framework: langgraph
# Generated: 2026-05-16T17:30:00Z
#
# faramesh dev    — run governance locally, no external infrastructure
# faramesh apply  — start enforcement
# Docs: https://docs.faramesh.dev

import "registry.faramesh.dev/frameworks/langgraph@1.0.0"

runtime {
  mode    = "enforce"
  wal_dir = "./faramesh-wal"
  backend = "sqlite"
}

# No provider declared — faramesh dev provides built-in stubs.
# For production, add a provider block. See: https://docs.faramesh.dev/providers

agent "my-app-agent" {
  # Tools discovered in this project:
  #   search_docs — ./agent.py:12 (@tool)
  #   send_email — ./agent.py:20 (@tool)

  rules {
    # All discovered tools defer by default. Review: faramesh approvals list
    # Change to permit after review: permit <tool-name>
    defer search_docs
    defer send_email
  }

  budget daily {
    max       = $10.00
    warn_at   = 0.8
    on_exceed = deny
  }

  egress {
    # No external egress permitted by default.
    # allow = ["api.example.com"]
  }
}
```

### 10.9 Terminal output (verbatim)

Implementers MUST print these strings exactly (including blank lines and two-space indentation in “Next steps”). Stdout only for success paths; errors on stderr.

**Branch A — framework detected, one or more tools discovered**

```
✓ Framework detected: langgraph
✓ Tools discovered: 2 (search_docs, send_email)
✓ governance.fms written

Next steps:
  Run your agent with governance:
    faramesh dev
  Review what your agent is doing:
    faramesh approvals list
  When ready for full enforcement:
    faramesh apply

Docs: https://docs.faramesh.dev/init
```

(Replace `langgraph` with `{{FRAMEWORK}}`, tool count and parenthesized list with discovered names comma-separated, no spaces after commas.)

**Branch B — framework detected, zero tools**

```
✓ Framework detected: langgraph

No tools discovered automatically.
Add rules to governance.fms manually.
See: https://docs.faramesh.dev/fpl

✓ governance.fms written

Next steps:
  Run your agent with governance:
    faramesh dev
  Review what your agent is doing:
    faramesh approvals list
  When ready for full enforcement:
    faramesh apply

Docs: https://docs.faramesh.dev/init
```

**Branch C — framework not auto-detected; user selected**

```
Framework not detected automatically.
Selected: langgraph

✓ governance.fms written

Next steps:
  Run your agent with governance:
    faramesh dev
  Review what your agent is doing:
    faramesh approvals list
  When ready for full enforcement:
    faramesh apply

Docs: https://docs.faramesh.dev/init
```

**Branch D — config already exists (stderr, exit 1)**

```
governance.fms already exists. To reinitialize, delete it first.
```

---

## 11. `faramesh dev` — terminal output (verbatim)

Phase 8 implements this exactly. `dev.md` in the public site is written only after Phase 8.

```
✓ governance.fms compiled
✓ in-process providers stubbed: vault (dev server), spiffe (ephemeral CA), kms (ephemeral RSA)
✓ WAL: in-memory
✓ enforcement: application-tier only (OS enforcement not active in dev mode)
→ Unix socket: /Users/alice/.faramesh/runtime/faramesh.sock
→ MCP proxy: http://127.0.0.1:8081/mcp
→ status: faramesh status
→ approvals: faramesh approvals list

Note: seccomp/Landlock not available on darwin. Production deployments on Linux provide full enforcement.
```

On Linux, omit the `Note:` line. On Windows, replace the `Note:` line with:

```
Note: seccomp/Landlock not available on windows. Network proxy enforcement is active. Production deployments on Linux provide full enforcement.
```

`→ Unix socket:` MUST print the actual socket path the daemon binds (default `~/.faramesh/runtime/faramesh.sock`, or `runtime.socket` from compiled config when set). `→ MCP proxy:` printed only when the compiled stack enables MCP proxy (e.g. agent `enforcement.mcp_proxy_port`).

---

## 12. Error message format contract

Every CLI error and adapter denial uses four elements: **location**, **what**, **why**, **fix**.

CLI format:

```
✗ [location]: [what]
  [why — one sentence]
  [fix — exact action]
```

### 12.1 CLI reference errors (verbatim)

**Missing provider reference**

```
✗ governance.fms:31 — credential "stripe" specifies backend "vault"
  No provider named "vault" is declared in this stack.
  Add a provider block before this agent block:

    provider "vault" {
      type  = "vault"
      addr  = env("VAULT_ADDR")
      token = env("VAULT_TOKEN")
    }
```

**Missing environment variable**

```
✗ governance.fms:12 — env("VAULT_ADDR") is not set
  This variable must be set before faramesh apply runs.
  Set it in your shell: export VAULT_ADDR=https://your-vault-addr
```

**deny! conflict**

```
✗ governance.fms:47 — deny! stripe/* conflicts with permit stripe/status at line 52
  deny! is unconditional and cannot be overridden by a downstream permit in the same agent block.
  Remove the permit at line 52, or change deny! to deny to allow exceptions.
```

### 12.2 Structured denial object (adapters only — JSON)

Never return a plain string to adapters. SDKs raise typed exceptions with these fields.

**Policy deny**

```json
{
  "code": "POLICY_DENY",
  "rule_id": "rule-stripe-refund-threshold",
  "rule_ref": "governance.fms:47",
  "human_message": "denied: stripe/refund above $500 requires approval",
  "resolution": {
    "type": "pending_approval",
    "approval_id": "apr-8821",
    "poll_url": "http://localhost:9090/approvals/apr-8821"
  }
}
```

**Rate exceeded**

```json
{
  "code": "RATE_EXCEEDED",
  "rule_id": "rate-stripe-charge",
  "rule_ref": "governance.fms:52",
  "human_message": "denied: stripe/charge rate limit (10/minute) exceeded",
  "resolution": {
    "type": "retry_after",
    "retry_after_seconds": 43
  }
}
```

**Budget ceiling**

```json
{
  "code": "BUDGET_EXCEEDED",
  "rule_ref": "governance.fms:31",
  "human_message": "denied: daily budget ceiling ($10.00) reached",
  "resolution": {
    "type": "budget_reset",
    "resets_at": "2026-05-17T00:00:00Z"
  }
}
```

**Budget warning (warn_at)**

```json
{
  "code": "BUDGET_WARNING",
  "human_message": "budget 80% consumed ($400.00/$500.00 daily), approval required to continue",
  "resolution": {
    "type": "pending_approval",
    "approval_id": "apr-9001"
  }
}
```

**Daemon not ready**

```json
{
  "code": "DAEMON_NOT_READY",
  "human_message": "denied: daemon is initializing, retry in a moment",
  "resolution": {
    "type": "retry_after",
    "retry_after_seconds": 2
  }
}
```

**Completion blocked**

```json
{
  "code": "COMPLETION_BLOCKED",
  "human_message": "agent cannot complete: 2 approvals pending",
  "resolution": {
    "type": "pending_approvals",
    "approval_ids": ["apr-8821", "apr-8822"]
  }
}
```

---

## 13. `completion_gate`

Evaluated at **Stop** lifecycle when the agent attempts to emit a final response.

```fpl
completion_gate {
  require no_open_approvals
  require budget_below_ceiling
  require all_deferred_resolved
}
```

Built-in conditions: `no_open_approvals`, `budget_below_ceiling`, `all_deferred_resolved`. Custom FPL boolean expressions over session state are allowed.

Failure → `COMPLETION_BLOCKED` (§11). Tier-1: GovernedToolSet intercepts completion signal; Tier-2: framework profile registers Stop hook.

---

## 14. `warn_at` (budget)

```fpl
budget daily {
  max       = $500.00
  warn_at   = 0.8
  on_exceed = deny
}
```

At 80% of ceiling, emit `BUDGET_WARNING` DEFER (§11). `warn_at` ∈ (0.0, 1.0). Applies to `daily`, `session`, and rolling budget scopes.

---

## 15. `reasoning_summary` (CAR / DPR)

Optional string on CAR; copied to DPR when set. Max 2048 characters; truncate with suffix `...[truncated]`.

| Framework | Source |
|-----------|--------|
| LangGraph | Last `AIMessage` content before tool call |
| Google ADK | Model reasoning trace from prior turn |
| OpenAI Agents SDK | Last assistant message content |

Not evaluated by policy engine. `faramesh explain` prints under label: `Agent reasoning before this call:`

---

## 16. Security invariants

**Config load-once:** Daemon reads governance config only during `apply` compilation. No fd or inotify watch on the file after compile. Optional `runtime { immutable_config = true }` → `chattr +i` on the config file after successful apply (default false).

**UID separation (production):** Daemon runs as system user `faramesh`. Agent processes run as a different unprivileged user not in group `faramesh`. `faramesh apply --check-uid` verifies; `--require-uid-separation` fails apply if not satisfied. `faramesh dev` may skip on developer machines.

**Seccomp baseline (Linux, non-relaxable):** deny: `kill`, `tkill`, `tgkill`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `kexec_load`, `perf_event_open`.

**systemd:** When `INVOCATION_ID` is set, emit `sd_notify WATCHDOG=1` on each WAL write; unit uses `WatchdogSec=30s`, `Restart=always`.

**eBPF LSM (optional):** `enforcement.ebpf_lsm = true` — block signals to daemon PID; requires Linux 5.7+ BPF LSM; `check` validates kernel support before `apply`.

---

## 17. Registry catalog

**Platform design (web app, API, GitOps):** [`docs/internal/FARAMESH_REGISTRY_PLATFORM.md`](../../../docs/internal/FARAMESH_REGISTRY_PLATFORM.md) — official registry in a **private** repo; `faramesh-core` implements the CLI contract (`internal/registry`, `internal/hub`).

Version pinning mandatory. Import forms (mutually exclusive artifact kinds):

- `import "registry.faramesh.dev/providers/<name>@<semver>"` — signed provider binary (download at apply)
- `import "registry.faramesh.dev/policies/<name>@<semver>"` — policy pack FPL (compile merge)
- `import "registry.faramesh.dev/frameworks/<name>@<semver>"` — framework profile FPL (compile merge)

Legacy: `import "registry.faramesh.dev/frameworks/langgraph@1.0.0"` remains valid. `@latest` is rejected.

**Providers — secrets:** `vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `1password`, `infisical`  
**Providers — identity:** `spiffe`, `okta`, `teleport`, `auth0`  
**Providers — KMS:** `aws-kms`, `gcp-kms`, `azure-kms`  
**Providers — audit sink:** `splunk-sink`, `datadog-sink`, `elastic-sink`, `s3-sink`, `gcs-sink`  
**Providers — cost:** `aws-cost`, `stripe-cost`, `openai-cost`  

**Domain packs:** `pci-dss`, `hipaa`, `soc2`, `gdpr`, `eu-ai-act`  
**Tool packs:** `stripe`, `github`, `aws`, `openai`, `kubernetes`, `database`, `filesystem`, `shell`  
**Framework profiles:** `langgraph`, `langchain`, `crewai`, `ag2`, `google-adk`, `openai-agents`, `anthropic-sdk`, `strands`, `bedrock`, `mcp`, `deep-agents`, `claude-code`, `cursor`, `opencode`

---

## 18. Enforcement tiers

| Tier | Mechanism | Frameworks (examples) |
|------|-----------|------------------------|
| 1 SDK shim | GovernedToolSet | LangGraph, LangChain, CrewAI, AG2, ADK, OpenAI Agents, Strands |
| 2 MCP proxy | Protocol proxy | Claude Code, Cursor, OpenCode |
| 3 HTTP proxy | Forward proxy | Bedrock Lambda, Strands distributed, AgentOS |
| 4 A2A | A2A proxy + inbound verify | Cross-vendor delegation |

**OS containment (Linux):** seccomp baseline auto; Landlock from `allowed_paths`; eBPF egress from `egress` block; Firecracker opt-in per tool (~125ms cold start).

**Platform matrix:** Linux full; macOS/Windows network proxy only; `faramesh apply --require-full-enforcement` exits non-zero off Linux.

---

## 19. `faramesh serve` flag → `governance.fms` inventory

Source: `cmd/faramesh/serve.go`. Destinations apply after Phase 2 compiler exists.

- `--policy` → agent/policy content lives in `governance.fms` agents; **DELETED** as daemon flag
- `--policy-url` → `runtime { policy_url, policy_poll_interval }` (optional remote policy fetch)
- `--policy-poll-interval` → `runtime { policy_poll_interval }`
- `--data-dir` → `runtime { wal_dir }` (default `~/.faramesh/runtime/data` maps to `./faramesh-wal` in stack dir for new stacks)
- `--socket` → `runtime { socket }` (default `~/.faramesh/runtime/faramesh.sock`)
- `--slack-webhook` → **DELETED** — use per-agent `alert { notify = "slack://..." }`
- `--log-level` → `runtime { log_level }`
- `--sync-horizon` → `runtime { horizon { enabled = true } }` (requires `faramesh auth login`)
- `--proxy-port` → per-agent `enforcement { http_proxy_port }`
- `--proxy-connect` → `enforcement { http_proxy_connect = true }`
- `--proxy-forward` → `enforcement { http_proxy_forward = true }`
- `--network-hardening-mode` → `runtime { network = "off"|"audit"|"enforce" }`
- `--inference-routes-file` → `runtime { inference_routes_file }`
- `--intent-classifier-url` → **DELETED** (probabilistic; violates engine invariants)
- `--intent-classifier-timeout` → **DELETED**
- `--intent-classifier-bearer-token` → **DELETED**
- `--allow-private-cidrs` → `runtime { allow_private_cidrs = [...] }`
- `--allow-private-hosts` → `runtime { allow_private_hosts = [...] }`
- `--grpc-port` → `runtime { grpc_port }`
- `--mcp-proxy-port` → `agent.enforcement { mcp_proxy_port }`
- `--mcp-target` → `agent.enforcement { mcp_target }`
- `--mcp-allowed-origins` → `agent.enforcement { mcp_allowed_origins = [...] }`
- `--mcp-edge-auth-mode` → `agent.enforcement { mcp_edge_auth_mode }`
- `--mcp-edge-auth-bearer-token` → `env` only via `runtime` or provider config; never inline
- `--mcp-protocol-version-mode` → `agent.enforcement { mcp_protocol_version_mode }`
- `--mcp-protocol-version` → `agent.enforcement { mcp_protocol_version }`
- `--mcp-session-ttl` → `agent.enforcement { mcp_session_ttl }`
- `--mcp-session-idle-timeout` → `agent.enforcement { mcp_session_idle_timeout }`
- `--mcp-sse-replay-enabled` → `agent.enforcement { mcp_sse_replay_enabled }`
- `--mcp-sse-replay-max-events` → `agent.enforcement { mcp_sse_replay_max_events }`
- `--mcp-sse-replay-max-age` → `agent.enforcement { mcp_sse_replay_max_age }`
- `--otlp-enabled` → `runtime { observability { otlp_enabled } }`
- `--otlp-endpoint` → `runtime { observability { otlp_endpoint } }`
- `--otlp-protocol` → `runtime { observability { otlp_protocol } }`
- `--otlp-insecure` → `runtime { observability { otlp_insecure } }`
- `--otlp-service-name` → `runtime { observability { otlp_service_name } }`
- `--otlp-service-version` → `runtime { observability { otlp_service_version } }`
- `--otlp-traces-enabled` → `runtime { observability { otlp_traces_enabled } }`
- `--otlp-metrics-enabled` → `runtime { observability { otlp_metrics_enabled } }`
- `--otlp-logs-enabled` → `runtime { observability { otlp_logs_enabled } }`
- `--metrics-port` → `runtime { observability { metrics_port } }`
- `--dpr-dsn` → `runtime { backend = "postgres", dsn = env("...") }`
- `--redis-url` → `runtime { session_backend = "redis", session_dsn = env("...") }`
- `--defer-backend` → `runtime { defer_backend = "memory"|"redis" }`
- `--defer-redis-prefix` → `runtime { defer_redis_prefix }`
- `--mode` → `runtime { mode = "enforce"|"shadow"|"audit" }`
- `--require-governance-before-network` → `runtime { require_governance_before_network = true }`
- `--dpr-hmac-key` → **DELETED** — KMS signing (Phase 7); dev uses ephemeral KMS stub
- `--tls-cert` → `runtime { tls { cert = env("...") } }`
- `--tls-key` → `runtime { tls { key = env("...") } }`
- `--client-ca` → `runtime { tls { client_ca = env("...") } }`
- `--tls-auto` → `runtime { tls { auto = true } }`
- `--pagerduty-routing-key` → `alert { notify = "pagerduty://...", on = "..." }` per agent
- `--policy-admin-token` → `runtime { admin { policy_token = env("...") } }`
- `--standing-admin-token` → `runtime { admin { standing_token = env("...") } }`
- `--ebpf` → `agent.enforcement { ebpf = "enforce"|"observe" }`
- `--ebpf-object` → `agent.enforcement { ebpf_object = "path" }`
- `--ebpf-attach-tracepoints` → `agent.enforcement { ebpf_attach_tracepoints = true }`
- `--spiffe-socket` → `identity "..." { type = "spiffe", socket = "..." }`
- `--spiffe-id` → agent `workload_id` or `identity` block reference
- `--vault-addr` → `provider "vault" { type = "vault", addr = env("VAULT_ADDR") }`
- `--vault-token` → `provider "vault" { token = env("VAULT_TOKEN") }`
- `--vault-mount` → `provider "vault" { mount = "secret" }`
- `--vault-namespace` → `provider "vault" { namespace = env("...") }`
- `--aws-secrets-region` → `provider "aws-sm" { type = "aws-sm", region = "..." }`
- `--gcp-secrets-project` → `provider "gcp-sm" { type = "gcp-sm", project = env("...") }`
- `--azure-vault-url` → `provider "azure-kv" { vault_url = env("...") }`
- `--azure-tenant-id` → `provider "azure-kv" { tenant_id = env("...") }`
- `--azure-client-id` → `provider "azure-kv" { client_id = env("...") }`
- `--azure-client-secret` → `provider "azure-kv" { client_secret = env("...") }`
- `--strict-preflight` → `runtime { preflight { strict = true } }`
- `--idp-provider` → `runtime { preflight { idp_provider = "..." } }`
- `--integrity-manifest` → `runtime { preflight { integrity_manifest = "..." } }`
- `--integrity-base-dir` → `runtime { preflight { integrity_base_dir = "..." } }`
- `--buildinfo-expected` → `runtime { preflight { buildinfo_expected = "..." } }`
- `--allow-env-credential-fallback` → **DELETED** — `faramesh dev` only
- `--skip-onboard-preflight` → **DELETED** — preflight is part of apply state machine

---

## 20. Hard invariants

1. Deterministic policy engine only — no LLM judges in the enforcement path.  
2. All providers via `ProviderService` — no vendor branches in the daemon.  
3. `apply` cannot skip `check`.  
4. WAL-first — no permit without durable DPR write.  
5. No governance during `STARTING` / `INITIALIZING`.  
6. Production DPR signing uses KMS outside the daemon process (Phase 7+).  
7. Errors and denials match §11–§12 verbatim — no paraphrasing in implementations.  
8. Config not re-read at runtime after compile.  
9. Seccomp baseline deny list cannot be relaxed per agent.

---

## 21. Implementation phases

| Phase | Scope | Status (implementation) |
|-------|--------|--------|
| 0a | This spec, proto, package stubs, delete legacy internal plans | SHIPPED |
| 0b | Public docs (`faramesh-docs`) | SHIPPED |
| 1 | FPL grammar + unified AST + YAML/JSON parsers | SHIPPED |
| 2 | Compiler + 13-command CLI; legacy surface removed | SHIPPED |
| 3 | ProviderService + sidecar launcher + registry binary download at apply | SHIPPED |
| 4 | Per-agent semantics + WAL budget/rate + redaction | SHIPPED (Landlock/Firecracker profiles optional) |
| 5 | CAR action types + DPR 2.0 | SHIPPED |
| 6 | Trust + A2A + async MCP tasks | SHIPPED (`faramesh/tasks/complete` MCP extension; Agent Card + delegate) |
| 7 | Cold start + Lamport + archival + KMS DPR + systemd watchdog | SHIPPED (provider KMS + archive manifest signing; `dpr_kms_provider` / `dpr_signer` in `runtime`) |
| 8 | `faramesh dev` | SHIPPED |
| 9a | Registry CLI contract (`internal/registry`, import resolve, hub client) | SHIPPED |
| 9b | Official registry service + GitOps catalog | SHIPPED (R0) — repo `faramesh-registry/`; web UI R4 |
| 9c | Provider binary download from registry manifest | SHIPPED |
| 10 | Remote mode (HTTPS) | SHIPPED (`FARAMESH_REMOTE_URL` / socket / `FARAMESH_BASE_URL`; Python + Node `transport`) |
| 11 | Cost, audit sinks, structured denials, warn_at, completion_gate, eBPF LSM | SHIPPED (CostEstimate in hot path; SinkDPR logs failures; BYO eBPF object) |
| 12 (v2.x) | Multi-tenancy, streaming response governance, budget pools | SHIPPED (`runtime.tenant_id`, `govern_tool_responses`, agent `budget_pools`) |

---

## 22. Deferred (v2.x)

- Multi-tenant stacks (separate WAL and policy namespaces per tenant).  
- Governing streamed tool **responses** (not just requests).  
- `budget_pool { }` for shared peer-agent ceilings.

Public documentation at https://docs.faramesh.dev is regenerated from implemented behavior after Phase 12, not before.
