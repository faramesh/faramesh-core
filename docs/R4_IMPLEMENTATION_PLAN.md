## R4 Implementation Plan — DPR Integrity & Operationalization

Goal
----
Deliver a production-ready operational layer (R4) that builds on the DPR/JCS/Ed25519 foundation:
- KMS-backed signing + key rotation
- Operator workflows for rotation & re-signing historical records
- Machine-verifiable signed migration reports
- Monitoring, CI conformance, and rollout plan

Scope & Non-Goals
------------------
- Scope: KMS integration, signer interface, CLI workflows, automated resigning/reporting, monitoring, tests, docs.
- Non-goal: Full external HSM procurement or cloud account provisioning (we design adapters and local mocks).

High-level Steps
----------------
1. KMS Signer Interface: define `Signer` abstraction and local file-based + KMS adapters.
2. Key Rotation API: design server-side rotation semantics (roll-forward, roll-back, grace period).
3. CLI: `faramesh key rotate dpr`, `faramesh key import dpr`, `faramesh key export dpr --verbose` (existing), `faramesh compliance resign --apply --report`.
4. Resign & Report: implement a signed, machine-verifiable migration report JSON that lists records re-signed, hashes, old/new key IDs, and operator signature.
5. CI & Tests: add JCS conformance corpus, signature verification tests, and end-to-end resign dry-run tests.
6. Monitoring: record verification metrics, alert rules for signature/hash failures, and dashboard guidance.
7. Docs & Ops: update runbooks, release notes, and operator checklists.

Signer interface (sketch)
-------------------------

```go
// Signer abstracts a signing backend (file-based, KMS, HSM).
type Signer interface {
    // ID returns a stable key identifier (e.g., sha256(pub) or KMS key ARN)
    ID() string
    // PublicKey returns the raw public key bytes (for storing with records)
    PublicKey() ([]byte, error)
    // Sign signs the input bytes and returns a signature blob
    Sign(data []byte) ([]byte, error)
}
```

Design notes
------------
- The pipeline will depend on a `Signer` rather than raw private keys when available. The daemon will construct a local file signer or a configured KMS signer.
- Each record's `SignerID` (already `SignerPublicKey` + `SignatureAlg`) will include `SignerID` to disambiguate rotated keys.
- Rotation: new key becomes active; records written after the activation are signed with new key. Rotation CLI will optionally trigger `compliance resign` for historical records.
- Resign `--dry-run` must be the default; `--apply` will persist. Produce a signed JSON report and (optionally) an append-only artifact stored under `cfg.DataDir/compliance-reports/`.

Migration report schema (outline)
--------------------------------
- report_id: uuid
- created_by: operator
- created_at: RFC3339
- old_signer_id
- new_signer_id
- records: [{record_id, old_hash, new_hash, re_signed: bool, note}]
- summary: counts
- operator_signature: {sig, signer_id}

Next immediate actions
----------------------
1. Implement the `Signer` interface and a local-file signer adapter.
2. Wire `Signer` into the daemon/pipeline so `Pipeline` can use it when configured.
3. Add `faramesh key rotate dpr` CLI scaffold.

Files to create/modify
-----------------------
- internal/core/dpr/signer.go (interface + file-based adapter)
- internal/daemon/daemon.go (load Signer from config)
- internal/core/pipeline.go (accept Signer instead of raw key)
- cmd/faramesh/key.go (rotation/import subcommands)
- cmd/faramesh/compliance.go (reporting flags and report output)
- docs/* (runbooks and this doc)

Risks & Mitigations
-------------------
- Risk: KMS latency or unavailable during writes — mitigation: local signer fallback and async resigning.
- Risk: Operator misuse during rotation — mitigation: require explicit `--apply`, create signed migration reports, and preserve old keys for a configurable grace period.

Acceptance criteria
-------------------
- `Signer` interface exists with at least a file-based adapter and tests.
- `faramesh key rotate dpr --dry-run` produces a preview; `--apply` executes rotation and optionally starts resign.
- Signed migration report is generated and verified by `faramesh compliance verify-report <report.json>`.
- CI contains JCS conformance checks and signature verification tests.

---
Created: 2026-05-01
Author: GitHub Copilot (acting as implementer)
