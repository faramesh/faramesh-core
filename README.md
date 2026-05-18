# Faramesh

- Website: https://faramesh.dev
- Documentation: https://docs.faramesh.dev
- Quickstart: https://docs.faramesh.dev/quickstart/
- Policy language (FPL): https://docs.faramesh.dev/fpl/
- Stack reference: https://docs.faramesh.dev/stack/

![Faramesh Docs cover](Readme-image.png)

Faramesh sits between an agent and its tools and decides every tool call against a policy you write. The daemon returns permit, defer, or deny decisions before the tool runs and records tamper-evident evidence for every decision.

The key capabilities of Faramesh are:

- Interception tiers so every call reaches the daemon: SDK shim, MCP proxy, HTTP proxy, and A2A proxy.
- Deterministic enforcement: steps 1 through 8 are pure functions over policy and the action payload, with no LLM in the decision path.
- Identity bound decisions using SPIFFE SVIDs, OIDC, or cloud workload identity.
- Credential brokering that mints short-lived scoped credentials at the call site so agents never hold long-lived secrets.
- Auditing with Decision Provenance Records, a hash-chained WAL, and optional KMS signing plus audit sinks for SIEM.

## Governance as code

Faramesh policy lives in a single stack file written in FPL (YAML and JSON map to the same AST). The CLI compiles that policy into a deterministic AST that the daemon enforces, and changes are applied atomically.

## Getting Started and Documentation

- Why Faramesh: https://docs.faramesh.dev/introduction/
- How Faramesh works: https://docs.faramesh.dev/concepts/how-it-works/
- Interception: https://docs.faramesh.dev/concepts/interception/
- Enforcement: https://docs.faramesh.dev/concepts/enforcement/
- Identity: https://docs.faramesh.dev/concepts/identity/
- Credentials: https://docs.faramesh.dev/concepts/credentials/
- Auditing: https://docs.faramesh.dev/concepts/auditing/
- Quickstart: https://docs.faramesh.dev/quickstart/
- Write your first policy: https://docs.faramesh.dev/guides/your-first-policy/
- Providers: https://docs.faramesh.dev/providers/
- CLI reference: https://docs.faramesh.dev/cli/

## Developing Faramesh

- Contributing guide: https://docs.faramesh.dev/guides/contributing/

## License

See [faramesh-core/LICENSE](LICENSE).
