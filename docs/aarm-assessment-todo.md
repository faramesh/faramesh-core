# AARM Assessment — Implementation Checklist (Faramesh Labs)

This checklist converts `aarm-assessment-faramesh-labs.md` into actionable items focused on the technical MUST/SHOULD gaps. Non-technical MUSTs (`C3`, `C4`) are noted but intentionally excluded from implementation here per guidance.

## Status Key
- ✅ Done
- 🔁 In progress
- ⬜ Not started

---

## MUST (technical)

- [🔁] R5-T: Tamper-Evident Receipts — migrate DPR signing to asymmetric keys (Ed25519), implement canonicalization (JCS/CBOR), and expose public keys for offline verification
  - Subtasks:
    - [🔁] Add Ed25519 signature fields to `Record` (signature, signature_algorithm, signer_public_key) — added.
    - [🔁] Implement Ed25519 sign/verify scaffold in `internal/core/dpr/signing.go` — added (uses existing canonical form for initial rollout).
    - [⬜] Replace/customize canonicalization with JCS (RFC 8785) implementation and re-sign DPRs.
    - [⬜] Update CLI/tools (`cmd/faramesh/audit*`, `cmd/faramesh/verify.go`) to verify Ed25519-signed DPRs and to publish/serve public keys (read-only endpoint or file in `data/keys/`).
    - [⬜] Migration notes: keep HMAC field during transition; toolchain must verify both kinds while migrating historical records.

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

## Notes / Current decisions

- We implemented Ed25519 fields and a signing/verification scaffold using the existing canonical bytes. This allows asymmetric signatures to be produced and verified during rollout while we implement full JCS canonicalization.
- HMAC remains supported for backward compatibility and migration tooling must accept both HMAC and asymmetric signatures until records are reissued or a migration policy is agreed.

---

If you'd like, I will:

1. Wire Ed25519 signing into the DPR write path (non-blocking fallback to HMAC if no key provided). (next step)
2. Add minimal CLI flags / data-dir persistence for a daemon Ed25519 key (optional; recommended for production).
3. Start a branch `feat/aarm-r5-ed25519` and open a PR with tests and docs.

Tell me which next action to take (I can start wiring signing into record writes now).
