# AARM Assessment — Implementation Checklist (Faramesh Labs)

This checklist converts `aarm-assessment-faramesh-labs.md` into actionable items focused on the technical MUST/SHOULD gaps. Non-technical MUSTs (`C3`, `C4`) are noted but intentionally excluded from implementation here per guidance.

## Status Key
- ✅ Done
- 🔁 In progress
- ⬜ Not started

---

## MUST (technical)

- [✅] R5-T: Tamper-Evident Receipts — migrate DPR signing to asymmetric keys (Ed25519), implement canonicalization (JCS/CBOR), and expose public keys for offline verification
  - Subtasks:
    - [✅] Add Ed25519 signature fields to `Record` (signature, signature_algorithm, signer_public_key).
    - [✅] Implement Ed25519 sign/verify scaffold in `internal/core/dpr/signing.go`.
    - [✅] Implement JCS canonicalization (RFC 8785); record-scoped algorithm; default for new records.
    - [✅] CLI verification/key publishing: `internal/core/dpr/verify.go` + `internal/core/dpr/kms_provider.go`.
    - [✅] Key rotation CLI: `faramesh key rotate dpr` (--generate, --new-key-file, --apply, dry-run default).
    - [✅] Signed migration report: `faramesh compliance resign --report`, `faramesh compliance verify-report`.
    - [✅] Migration notes: HMAC retained for backward compatibility during rollout.
    - [✅] KMS provider registry: pluggable infrastructure for community providers (AWS KMS, GCP KMS, Azure, etc.).

- [⬜] R4-T: Authorization Decisions — implement `MODIFY`, `STEP_UP`, and DEFER cascade tracking
  - Subtasks:
    - [⬜] Add `MODIFY` effect semantics in policy lowering and runtime.
    - [⬜] Add `STEP_UP` effect and routing for elevated approvals.
    - [⬜] Implement DEFER dependency graph and configurable cascade limits.
    - [⬜] Add unit tests covering MODIFY/STEP_UP/DEFER-cascade behaviors.

## SHOULD (technical)

- [⬜] R7-T: Semantic Distance Tracking — embedding-based drift detection and calibration
  - Subtasks:
    - [⬜] Add `internal/core/semantic` provider abstraction for embeddings + cache.
    - [⬜] Implement cosine similarity helpers and integrate into `AggregationGovernor`.
    - [⬜] Create calibration dataset (benign vs malicious sequences) and thresholding tooling.

## Non-technical (not implemented here)

- [⬜] C3-G: Production deployment with paying customers — OUT OF SCOPE (ops)
- [⬜] C4-G: Security certification (SOC2 / ISO27001 / FedRAMP) — OUT OF SCOPE (org)

---

## Implementation Summary

### R5-T: Tamper-Evident Receipts (✅ Complete)

**Files Added/Modified:**
- Core: `internal/core/dpr/signing.go`, `internal/core/dpr/signer.go`, `internal/core/dpr/kms_signer.go`, `internal/core/dpr/kms_provider.go`, `internal/core/dpr/kms_provider_init.go`, `internal/core/dpr/verify.go`, `internal/core/dpr/report.go`
- Canonicalization: `internal/core/canonicalize/jcs.go` + tests
- Pipeline: `internal/core/pipeline.go` (SetSigner, prefer Signer over raw keys)
- Daemon: `internal/daemon/daemon.go` (DPRSigner config, load Signer)
- CLI: `cmd/faramesh/key_rotate.go`, `cmd/faramesh/compliance.go` (resign/verify-report)
- Docs: `docs/R4_IMPLEMENTATION_PLAN.md`

**Key Design:**
- Record-scoped `CanonicalizationAlgorithm`; JCS default for new records.
- Pluggable KMS provider registry (`RegisterKMSProvider`) for extensibility.
- Built-in providers: `file://` (on-disk) and `localkms://` (on-prem KMS).
- Community-contributed providers (AWS KMS, GCP KMS, Azure, etc.) can be added via `dpr.RegisterKMSProvider()`.
- Signed migration reports enable operator audit trails.
- Ed25519 verification tied to canonical bytes and record hash validity.

**Backward Compatibility:**
- HMAC field retained; toolchain verifies both during transition.
- Legacy records treated as LegacyJSON canonicalization.

### R4-T: Authorization Decisions (⬜ Next Priority)

Plan: MODIFY effect (workflow branching), STEP_UP effect (elevated approvals), DEFER cascade (dependency tracking).

### R7-T: Semantic Distance Tracking (⬜ Future)

Plan: Embeddings provider abstraction, cosine similarity, drift detection against known-safe sequences.

---

## Community Provider Integration

To add a new KMS provider (e.g., AWS KMS):

1. Create provider package with factory function implementing:
   ```go
   func NewAWSKMSSigner(uri, dataDir string) (dpr.Signer, error) { ... }
   ```

2. Register in `init()`:
   ```go
   func init() {
       dpr.RegisterKMSProvider("aws-kms", NewAWSKMSSigner)
   }
   ```

3. URI format: `aws-kms://alias/key-alias` or `aws-kms://arn:aws:kms:...`

4. Submit PR with tests and docs.

**Next Steps:** Begin R4-T (MODIFY/STEP_UP/DEFER effects).
