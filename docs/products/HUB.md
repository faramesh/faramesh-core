# Hub — Policy Pack Registry PRD

**Product:** Faramesh Hub  
**Repo (planned):** `faramesh/hub` (registry backend) + policy packs shipped as sub-dirs of `faramesh/faramesh-core`  
**License:** Registry: Proprietary SaaS. Policy packs: Apache 2.0 (community), commercial (verified packs)  
**Relationship to Core:** Hub distributes policy packs that are installed into Core. Core ships with 15 built-in packs. Hub is npm for governance policies.

---

## Problem Statement

Every governed agent needs a policy file. Writing policies from scratch is a barrier to adoption. Engineers in fintech, healthcare, DevOps, and SaaS each have the same basic governance needs: don't let the agent delete production data, don't let it send emails without approval, cap its spending. These patterns should be one-line imports, not hand-written per deployment.

Additionally, policy packs are compliance artifacts. A "PCI-DSS v1" policy pack, if published and maintained by an organization known to the compliance community, reduces the audit burden of proving your agent governance meets PCI requirements.

---

## Built-in Packs (ship with Core, zero install)

```yaml
# One-line import
extends: faramesh/packs/saas-refunds-v1
```

| Pack | Domain | Key Rules |
|------|---------|-----------|
| `saas-refunds-v1` | SaaS/Billing | Refund thresholds by tier, idempotency key required |
| `infra-operations-v2` | DevOps | Shell command allowlist, deployment approval |
| `delete-safety-v1` | Data Safety | All delete operations require DEFER, soft-delete preferred |
| `hipaa-phi-v1` | Healthcare | PHI output redaction, access logging, audit trail |
| `pci-dss-v1` | Financial | PAN redaction, cardholder data access limits |
| `sox-audit-v1` | Finance/Compliance | Financial data access logging, change approval |
| `llm-inference-budget-v1` | Cost Control | Per-session token/cost limits, model selection governance |
| `devops-shell-v1` | DevOps | Shell classifier, deployment gates, environment restrictions |
| `customer-service-v1` | SaaS | Refund limits by tier, escalation patterns, PII output scan |
| `research-agent-v1` | Research | URL allowlist, output size limits, no external API writes |

---

## Hub Registry Features

### Pack Discovery
- **Search by domain:** `faramesh hub search fintech`
- **Browse by framework:** packs designed for LangChain, CrewAI, MCP, AutoGen, Google ADK
- **Verified badge:** human review by Faramesh Labs team confirms the pack is correct, non-malicious, and aligns with stated compliance standard
- **Namespace ownership:** domain verification (DNS TXT or HTTPS proof) required to claim a namespace (e.g., `stripe/` requires proving control of stripe.com)
- **Download counts, GitHub stars, last-updated:** community quality signals

### Pack Security
- **Cryptographic signing:** every pack is signed at publish time with the publisher's Hub account key (HSM-backed). CLI verifies signature on install
- **Lockfile:** `faramesh.lock` pinning every installed pack to exact version + SHA256 hash (like `package-lock.json`)
- **Supply chain protection:** Hub CDN serves signed content; BGP/DNS hijacks cannot serve malicious packs because CLI verifies signatures
- **Hub pack SBOM:** each pack includes a manifest of what rules it adds and why

### Pack Install/Update
```bash
faramesh hub install stripe/agent-governance-v1   # install and verify signature
faramesh hub install stripe/agent-governance-v1@1.2.0  # pin to version
faramesh hub update                                # update all installed packs to latest
faramesh hub list                                  # list installed packs + versions
faramesh hub verify                                # re-verify all installed pack signatures
faramesh hub search hipaa                          # search the registry
```

### Pack Authoring
```bash
faramesh hub init my-pack          # scaffold a new pack
faramesh hub validate my-pack/     # validate pack structure + policy syntax
faramesh hub publish my-pack/      # publish to Hub (requires Hub account, namespace ownership)
faramesh hub sign my-pack.tar.gz   # sign a pack locally
```

---

## Pack Format

```
my-pack/
├── pack.yaml           # metadata: name, version, description, domain, rules-summary
├── policy.yaml         # the FPL rules (importable via extends:)
├── tests/
│   └── test-suite.yaml # policy-test suite (required for publication)
├── fixtures/
│   └── regression.yaml # DPR fixture regression tests
└── README.md           # installation + customization guide
```

```yaml
# pack.yaml
name: stripe/agent-governance-v1
version: 1.2.0
description: "Governance rules for Stripe API tool calls"
domain: [saas, billing, fintech]
author: Stripe Inc.
namespace_verified: true
license: Apache-2.0
faramesh_core_min: 1.1.0
rules_summary:
  - "Defer refunds > $500 for free-tier principals"
  - "Deny charges to sanctioned card countries"
  - "Require idempotency key on all charge operations"
```

---

## Policy Composition Model (Multi-File)

When multiple packs are installed, composition rules are explicit:

```yaml
# faramesh/policy.yaml
faramesh-version: "1.1"
extends:
  - faramesh/packs/saas-refunds-v1      # base layer
  - stripe/agent-governance-v1          # add-on
  
composition: first-match-across-all     # or: per-file-then-merge

# Custom rules ALWAYS evaluated last (lowest priority)
# extends rules evaluated in order listed
rules:
  - id: custom-001
    match: { tool: "stripe/refund", when: "args['amount'] > 5000" }
    effect: deny
    reason: "Local policy: refunds above $5000 blocked"
```

Composition semantics:
- `first-match-across-all`: rules from all files merged in declaration order; first-match-wins globally
- `per-file-then-merge`: each file evaluated independently; most restrictive outcome wins

---

## Community Contribution Incentives

The npm problem: packages exist because contributors get reputation. Hub packs need the same mechanism.

- **Publisher Profile:** each Hub account has a profile with published packs, download counts, and aggregate review score
- **Pack Leaderboard:** top packs by downloads/month, featured in CLI (`faramesh hub popular`)
- **"Contributed by" credibility:** policy pack authorship linked to GitHub account and professional profile
- **Enterprise Sponsorship:** Faramesh Labs pays $500-$5000 bounties for first high-quality packs in underserved domains (healthcare, government, defense)
- **Certification Program:** "Faramesh Certified Compliance Pack" designation after independent audit

---

## Monetization

- **Free:** install and use any public pack, unlimited
- **Hub Pro ($49/month):** private packs (publish packs only visible to your org), audit logs of pack installations
- **Enterprise:** SLA-backed pack maintenance, legal indemnification for compliance packs, private registry mirror

---

## Build Order

1. **v0.1**: Built-in packs ship with Core (`extends: faramesh/packs/*`) — no registry needed
2. **v0.2**: `faramesh hub search/install/list` against a static GitHub-hosted registry (YAML manifest)
3. **v0.3**: Web registry UI + pack publishing workflow
4. **v0.4**: Cryptographic signing + lockfile
5. **v0.5**: Namespace ownership verification
6. **v1.0**: Full community registry with reputation system + Enterprise tier
