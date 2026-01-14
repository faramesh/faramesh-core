# Changelog

All notable changes to Faramesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- **0.2.0** - Enhanced integrations, DX features, security improvements, documentation rewrite
- **0.1.0** - Initial public release

---

## See Also

- [Roadmap](ROADMAP.md) - Product roadmap and future phases
- [Architecture](ARCHITECTURE.md) - System architecture
- [Contributing](CONTRIBUTING.md) - Contribution guidelines
