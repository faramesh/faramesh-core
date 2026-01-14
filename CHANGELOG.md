# Changelog

All notable changes to Faramesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-01-14

### Added

- **Execution Gate (`POST /v1/gate/decide`)**:
  - Decide-only endpoint for pre-checking actions without creating DB records
  - Returns deterministic decision with full version-bound metadata
  - Supports EXECUTE / ABSTAIN / HALT outcomes with machine-readable reason codes

- **Deterministic Canonicalization & Request Hashing**:
  - `canonicalize()` - Deterministic JSON serialization (sorted keys, normalized floats, no NaN/Infinity)
  - `compute_request_hash()` - SHA-256 hash of canonical action payload
  - Identical logical payloads (different key ordering) produce identical hashes
  - Strict fail-closed behavior on invalid inputs

- **Execution Profiles**:
  - YAML-based execution profiles with tool allowlists and constraints
  - `profiles/default.yaml` - Default profile configuration
  - Profile enforcement in decision pipeline
  - Profile version and hash binding for auditability

- **Decision Outcomes & Reason Codes**:
  - `DecisionOutcome` enum: EXECUTE, ABSTAIN, HALT
  - Canonical reason codes: POLICY_ALLOW, POLICY_DENY, POLICY_REQUIRE_APPROVAL, PROFILE_DISALLOWS_TOOL, INTERNAL_ERROR, etc.
  - Extended action model with outcome, reason_code, reason_details fields

- **Version Binding & Provenance**:
  - `request_hash` - Hash of canonical action payload
  - `policy_hash` - Hash of policy configuration
  - `profile_hash` - Hash of execution profile
  - `runtime_version` - Faramesh version string
  - `provenance_id` - Combined hash for replay verification

- **Tamper-Evident Audit Log**:
  - Hash-chained event records with `prev_hash` and `record_hash`
  - Append-only audit trail for all action events
  - CLI verification: `faramesh verify-log <action-id>`

- **Decision Replay**:
  - CLI command: `faramesh replay-decision <action-id>`
  - Re-runs gate evaluation and compares with stored decision
  - Detects policy/profile changes since original decision

- **Conformance Test Suite**:
  - `tests/test_conformance.py` - Comprehensive conformance tests
  - Determinism tests (identical payloads → identical decisions)
  - Fail-closed behavior tests (malformed input → HALT)
  - Profile enforcement tests
  - Audit chain verification tests
  - Replay discipline tests

- **CLI Enhancements**:
  - `faramesh verify-log <action-id>` - Verify audit chain integrity
  - `faramesh replay-decision <action-id>` - Replay and verify decision
  - Enhanced `faramesh explain` with outcome and reason_code display

### Changed

- **Action Model**: Extended with execution gate fields (outcome, reason_code, request_hash, policy_hash, profile_hash, runtime_version, provenance_id)
- **API Responses**: All action responses now include version-bound metadata
- **Decision Engine**: Centralized decision logic with fail-closed semantics

### Security

- Fail-closed semantics: any parse error, schema error, or internal error results in HALT (no execution)
- Strict Pydantic schemas with `extra="forbid"` reject unknown fields
- Tamper-evident audit chain detects modifications

---

## [0.2.0] - 2026-01-13

### Added

- **Framework Integrations**: One-line governance for 6 frameworks
  - LangChain (enhanced)
  - CrewAI (new)
  - AutoGen (new)
  - MCP (new)
  - LangGraph (new)
  - LlamaIndex (new)

- **Developer Experience (DX) Features**:
  - `faramesh init` - Scaffold starter layout
  - `faramesh doctor` - Environment sanity checks
  - `faramesh explain <id>` - Explain policy decisions
  - `faramesh policy-diff` - Compare policy files
  - `faramesh init-docker` - Generate Docker configuration
  - `faramesh tail` - Stream live actions via SSE
  - `faramesh replay <id>` - Replay actions

- **Policy Hot Reload**: 
  - `--hot-reload` flag for automatic policy reloading
  - `FARAMESH_HOT_RELOAD` environment variable
  - Failure-safe reload (keeps previous valid policy on error)

- **Enhanced CLI**:
  - Prefix matching for action IDs
  - Color-coded output (with `rich` optional dependency)
  - JSON output support (`--json` flag)
  - Enhanced table formatting

- **Security Enhancements**:
  - Comprehensive input validation
  - Command sanitization
  - Optimistic locking for concurrency control
  - Enhanced error handling with safe failure modes
  - Security guard module (`src/faramesh/server/security/guard.py`)

- **Documentation**:
  - Complete documentation rewrite
  - Comprehensive API reference
  - Detailed CLI reference
  - Framework integration guides
  - Security guardrails documentation
  - Policy packs documentation

- **Policy Packs**:
  - `saas_refunds.yaml` - SaaS refund operations
  - `infra_shell_limits.yaml` - Infrastructure automation
  - `marketing_bot.yaml` - Marketing automation
  - `restrict_http_external.yaml` - External HTTP restrictions

- **SDK Enhancements**:
  - Policy models for programmatic policy building
  - Policy validation helpers
  - Enhanced error handling
  - Telemetry callbacks

### Changed

- **Project Structure**: Renamed from `fara-core` to `faramesh-core`
- **SDK API**: Modern functional API (`submit_action`, `configure`) with legacy class-based API still supported
- **Error Handling**: Comprehensive error classes and safe failure modes
- **Policy Engine**: Enhanced validation and error messages

### Fixed

- Input validation edge cases
- Race conditions in concurrent scenarios
- Error handling improvements
- Documentation accuracy

### Security

- Enhanced input validation
- Command sanitization improvements
- Optimistic locking implementation
- Safe failure modes to prevent server crashes

---

## [0.1.0] - 2025-12-XX

### Added

- **Initial Release**: Faramesh Core open-source execution governor

- **Core Features**:
  - Policy-driven governance with YAML policies
  - Risk scoring (low/medium/high)
  - Human-in-the-loop approval workflows
  - REST API (`/v1/actions`, `/v1/events`, etc.)
  - Web UI for monitoring and approvals
  - CLI for action management
  - SQLite and PostgreSQL support

- **SDKs**:
  - Python SDK (`faramesh`)
  - Node.js SDK (`@faramesh/sdk`)

- **Integrations**:
  - LangChain integration (`GovernedTool`)

- **CLI Commands**:
  - `faramesh serve` - Start server
  - `faramesh migrate` - Run migrations
  - `faramesh list` - List actions
  - `faramesh get <id>` - Get action details
  - `faramesh approve/deny <id>` - Approve/deny actions
  - `faramesh events <id>` - View event timeline
  - `faramesh explain <id>` - Explain policy decisions

- **Documentation**:
  - Basic README
  - Quick start guide
  - API documentation
  - CLI documentation

### License

- Elastic License 2.0

---

## [Unreleased]

### Planned

- Enhanced policy packs
- More framework integrations
- Advanced analytics
- Bulk operations
- Policy templates

---

## Version History

- **0.3.0** - Execution gate, deterministic hashing, tamper-evident audit, decision replay, execution profiles
- **0.2.0** - Enhanced integrations, DX features, security improvements, documentation rewrite
- **0.1.0** - Initial public release

---

## See Also

- [Roadmap](ROADMAP.md) - Product roadmap and future phases
- [Architecture](ARCHITECTURE.md) - System architecture
- [Contributing](CONTRIBUTING.md) - Contribution guidelines
