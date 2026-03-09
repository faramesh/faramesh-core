# Horizon — Enterprise Control Plane PRD

**Product:** Faramesh Horizon  
**Repo (planned):** `faramesh/horizon`  
**License:** Commercial (yearly contract, SaaS and self-hosted tiers)  
**Relationship to Core:** Horizon is the fleet-wide, multi-tenant, compliance-grade control plane built entirely on top of Faramesh Core. Core is the enforcement primitive. Horizon is the glass pane, the audit console, and the fleet brain.

---

## Problem Statement

When an enterprise deploys 50+ governed agents across multiple teams, they need:
- A single pane of glass across all agents, all decisions, all pending approvals
- Compliance exports that satisfy SOC 2, ISO 27001, HIPAA, and PCI-DSS auditors
- Policy governance at the org level (mandatory baseline policies that cannot be overridden by individual teams)
- Fleet-wide kill switches, policy pushes, and anomaly detection
- Advanced PIE (Policy Intelligence Engine) analysis on large DPR datasets
- DEFER approval routing with SLAs, escalation, multi-approver workflows, and Slack/PagerDuty integrations
- Enterprise SSO (Okta, Azure AD, Google Workspace) for human approver identity

Faramesh Core provides all of this data. Horizon provides the interface and the orchestration.

---

## Core Features

### Layer 1: Fleet Management Dashboard
- **Agent Registry:** all agents, current policy version hash, session state, DEFER queue depth, last-seen
- **Real-time Decision Stream:** live feed across all agents (faramesh tail at fleet scale), filterable by outcome/agent/tool
- **Fleet-wide Kill Switch:** deny all future actions for any agent or tool pattern fleet-wide, propagated via Redis Pub/Sub in <100ms
- **Policy Push:** push a policy update to all agents, selected agents, or glob patterns (`*-production`, `staging-*`)
- **DEFER Approval Queue:** centralized inbox for all pending approvals across all agents, sortable by risk/urgency, batch approval

### Layer 2: Compliance and Audit
- **DPR Chain Explorer:** visualize the hash chain for any agent, verify integrity, browse records with full context
- **Compliance Export:** generate SOC 2 audit package, HIPAA audit log, PCI-DSS evidence pack from DPR chain records
- **Custom Report Builder:** query DPR records by agent, tool, outcome, date range, risk score, policy version
- **Chain Integrity Monitor:** continuous background verification; alerts on any hash chain violation
- **Retention Policies:** configurable per agent (7 years for financial, indefinite for critical infrastructure)
- **Write-Once Storage:** S3 Object Lock or Azure Blob Immutability integration for tamper-evident archives

### Layer 3: Policy Intelligence Engine (PIE) — Fleet Scale
- **Dead Rules Analysis:** identify rules never triggered in any agent in the last N days
- **Approval Pattern Analysis:** DEFER rules with consistently high approval rates → PERMIT candidates with confidence scores
- **Argument Drift Detection:** flag when argument distributions shift from baseline across the fleet
- **Policy Coverage Report:** which tools are unmatched by policy across the entire fleet
- **Policy Diff Across Agents:** compare which agents have diverged from the org-mandated baseline
- **Behavioral Fingerprinting:** per-agent, per-model behavioral envelope calibration and drift detection

### Layer 4: Advanced DEFER Workflow
- **Priority Routing:** critical/high/normal tiers with different SLAs and channels
- **Escalation Chains:** if primary approver doesn't respond in N minutes, escalate to secondary
- **Multi-Approver Workflows:** require M of N approvers for high-risk actions
- **Batch Approval:** approve/deny multiple pending DEFERs of the same type simultaneously
- **Conditional Approval:** approver can modify arguments before execution; modifications re-canonicalized and logged
- **Approval Channels:** Slack (blocks), PagerDuty (incidents), Microsoft Teams, email, SMS (Twilio), webhook
- **Approval Audit Trail:** every approval decision recorded with approver identity (IDP-verified), timestamp, modification

### Layer 5: Enterprise Identity
- **SSO Integration:** Okta, Azure AD / Entra ID, Google Workspace, Auth0, Keycloak (SAML 2.0 and OIDC)
- **RBAC for Horizon:** Viewer, Approver, Policy Author, Fleet Admin, Org Owner
- **Mid-session Principal Elevation:** analyst → operator with MFA verification, elevation TTL, IDP revocation events
- **IDP Revocation Webhooks:** receive real-time revocation events from Okta/AzureAD, immediately revoke elevated sessions
- **Approver Identity Verification:** every DEFER approval records the approver's IDP-verified identity

### Layer 6: Multi-Tenancy
- **Org Isolation:** complete isolation between tenant orgs (separate database schemas, separate Redis keyspaces, separate encryption keys)
- **Org-Level Mandatory Baselines:** org admin can push baseline policy rules that are prepended to every agent's policy, non-overridable
- **Shadow Agent Detection:** identify agents operating outside any governance perimeter
- **Policy Adoption Metrics:** what % of agents in the org are governed, what % meet the org baseline

### Layer 7: Self-Hosted Tier (Enterprise Gate)
- **On-Premises Deployment:** full Horizon stack deployable in customer VPC (Helm chart + Terraform module)
- **Air-Gapped Mode:** operates with no Faramesh Labs connectivity
- **Bring Your Own Key (BYOK):** customer manages encryption keys for DPR storage
- **Private Link:** AWS PrivateLink / Azure Private Endpoint for all Horizon API traffic
- **FedRAMP Roadmap:** separate track for US federal customers

---

## Data Model Extensions (on top of Core DPR)

```sql
-- Horizon-only tables (not in Core)
CREATE TABLE approvals (
    id UUID PRIMARY KEY,
    defer_dpr_record_id UUID NOT NULL,
    agent_id TEXT NOT NULL,
    approver_identity TEXT NOT NULL,       -- IDP-verified
    approver_idp TEXT NOT NULL,            -- okta, azure_ad, google
    approval_method TEXT NOT NULL,         -- slack, pagerduty, api, web_ui
    outcome TEXT NOT NULL,                 -- approved, denied
    modified_args JSONB,                   -- if approver modified args
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE fleet_policies (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    policy_yaml TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    activated_by TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL,
    is_baseline BOOLEAN DEFAULT FALSE      -- org-mandated, non-overridable
);

CREATE TABLE agent_registry (
    agent_id TEXT PRIMARY KEY,
    org_id UUID NOT NULL,
    current_policy_hash TEXT,
    last_seen TIMESTAMPTZ,
    kill_switch_active BOOLEAN DEFAULT FALSE,
    metadata JSONB
);
```

---

## Architecture

```
Horizon Control Plane
├── API Server (Go/gRPC + REST gateway)
│   ├── Fleet Management API
│   ├── Approval Workflow API
│   ├── Compliance Export API
│   └── Policy Intelligence API
├── DPR Aggregator (Kafka consumer → PostgreSQL)
│   ├── Receives DPR stream from all Core instances
│   └── Runs cross-agent sequence analysis (Sverm integration)
├── Notification Engine
│   ├── Slack / PagerDuty / Teams / Email adapters
│   └── SLA monitoring + escalation scheduler
├── PIE Engine (batch + streaming)
│   ├── Materialized views (PostgreSQL)
│   └── Incremental aggregation triggers
└── Web UI (Next.js)
    ├── Fleet Dashboard
    ├── DEFER Approval Inbox
    ├── DPR Chain Explorer
    └── Policy Editor
```

---

## Integration with Core

Core instances push DPR records to Horizon via:
1. **Direct streaming** (when `faramesh serve --horizon-endpoint` is set): Core streams records via gRPC to Horizon in real-time
2. **Batch sync** (`faramesh sync --to horizon`): periodic sync of WAL records to Horizon
3. **Pull** (Horizon polls Core's read API): for low-volume deployments

```bash
faramesh login                    # authenticate with Horizon
faramesh serve --sync-horizon     # enables real-time DPR streaming to Horizon
```

---

## Monetization

- **Team:** $299/month — up to 10 agents, Slack DEFER routing, DPR explorer
- **Business:** $999/month — unlimited agents, PIE analysis, SSO, multi-approver workflows
- **Enterprise:** custom — self-hosted, BYOK, mandatory baselines, FedRAMP roadmap, dedicated support

---

## Build Order

1. **v0.1**: DPR ingestion API + basic fleet dashboard (agent list, live decision stream)
2. **v0.2**: DEFER approval inbox (Slack + Web UI approval)
3. **v0.3**: PIE analysis (dead rules, approval patterns)
4. **v0.4**: Compliance export (SOC 2 package)
5. **v0.5**: SSO + RBAC
6. **v1.0**: Multi-tenancy + mandatory baselines + self-hosted tier
