# Faramesh Governance

Faramesh is an open source project for deterministic policy enforcement around
AI agent tool calls, MCP/API access, local decision APIs, policy packs, SDKs,
and audit evidence. Project decisions are made in public through GitHub issues,
pull requests, discussions, and maintainer review.

## Scope

The open source project includes:

- the Faramesh runtime and local decision daemon;
- the Faramesh Policy Language (FPL) and policy evaluation pipeline;
- MCP/API governance primitives required for local adoption;
- SDKs and adapters required to integrate with common agent frameworks;
- the community registry for neutral policy packs, providers, and framework
  profiles;
- local audit, evidence, and replay primitives;
- public documentation, examples, tests, and reference deployment materials.

Commercial products and services may integrate with Faramesh, package it, or
provide additional operational workflows. They do not control project governance
or change the requirement that the open source runtime remain useful without a
proprietary service in the decision path.

## Roles

### Contributors

Contributors submit issues, documentation, tests, policy packs, adapters, SDK
changes, bug fixes, and design proposals.

### Maintainers

Maintainers review and merge pull requests, triage issues, manage releases,
enforce the Code of Conduct, coordinate security response, and make technical
decisions for their areas of ownership.

Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Decision Making

Faramesh uses lazy consensus for routine changes. A change may merge after
maintainer approval, CI success, DCO sign-off, and a reasonable review window.

Changes that affect public APIs, FPL semantics, security boundaries,
governance, release policy, or repository scope require explicit maintainer
approval and should include a design issue or proposal before implementation.

Security-sensitive changes require review by at least two maintainers when two
maintainers are available. If only one maintainer is available for an urgent
security fix, the fix may be merged and documented after the release.

## Maintainer Changes

New maintainers are added based on sustained, high-quality contribution,
trustworthiness in review, and demonstrated care for users and project
direction. A candidate should normally have multiple non-trivial merged
contributions or significant recurring review, documentation, security, release,
or community work.

A maintainer may step down at any time. Maintainers who are inactive for an
extended period may be moved to emeritus status by consensus of the active
maintainers.

## Contribution Policy

Faramesh uses the Developer Certificate of Origin (DCO). All commits must be
signed off with `git commit -s`.

AI-assisted contributions are allowed when the contributor understands the
change, tests it, and takes responsibility for it. Fully automated, low-signal,
or undisclosed bulk AI-generated pull requests may be closed.

## Security

Security reports are handled according to [SECURITY.md](SECURITY.md). Do not
open public issues for vulnerabilities.

## Code of Conduct

All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
