# Faramesh Roadmap

This roadmap tracks the open source Faramesh project. Dates are intentionally
omitted until work is scheduled in public issues.

## 1. CNCF Readiness

- Re-license in-scope code repositories to Apache-2.0.
- License documentation under CC-BY-4.0.
- Keep governance, maintainers, security, contribution, and roadmap documents
  current.
- Enable DCO checks on all in-scope repositories.
- Publish a clear project/product separation statement.

## 2. Decision Plane Contract

- Stabilize the local decision API used by SDKs, MCP proxies, HTTP/API
  gateways, and adapters.
- Standardize decision inputs, effects, obligations, reason codes, policy
  versions, latency metadata, and evidence identifiers.
- Add compatibility tests for SDKs and adapters against the decision contract.

## 3. Context-Aware Policy Engine

- Make context providers explicit, typed, observable, and fail-closed.
- Support identity, session, risk, environment, budget, and external evidence as
  structured policy inputs.
- Preserve deterministic evaluation and auditable policy decisions.

## 4. MCP and API Governance

- Harden MCP tool, resource, prompt, and server mediation.
- Improve HTTP/API governance for agents that act through SaaS, internal APIs,
  CI/CD systems, and cloud APIs.
- Extend policy examples for common agent action surfaces.

## 5. Evidence, Audit, and Replay

- Strengthen Decision Provenance Records and hash-chained WAL verification.
- Improve replay workflows for debugging policy changes against historical
  decisions.
- Publish compliance-oriented examples without requiring a hosted service.

## 6. Registry and Ecosystem

- Keep the community registry neutral and reproducible.
- Add community policy packs, framework profiles, and providers through signed
  contributions.
- Document review expectations for new registry artifacts.

## 7. Deployment Hardening

- Publish reference deployments for local development, Kubernetes, CI/CD, and
  serverless environments.
- Improve observability and health reporting for self-hosted operation.
- Keep Faramesh usable without a proprietary control plane in the decision path.
