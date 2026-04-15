package packs

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

//go:embed faramesh-*/*
var bundledPolicies embed.FS

type bundledPackDef struct {
	Dir                 string
	Name                string
	Version             string
	Description         string
	TrustTier           string
	SupportedFrameworks []string
	ActionSurfaces      []string
	Assumptions         []string
	RulesSummary        *hub.PackRulesSummary
	ApprovalDefaults    []hub.PackApprovalDefault
	CredentialExpect    []hub.PackCredentialExpect
	ObserveEnforce      *hub.PackObserveEnforce
	ExampleIncidents    []string
	Dependencies        []string
	Compatibility       map[string]string
	Changelog           string
	RiskModel           *hub.PackRiskModel
}

var bundledPackDefs = []bundledPackDef{
	{
		Dir:                 "faramesh-coding-agent",
		Name:                "faramesh/coding-agent",
		Version:             "1.0.0",
		Description:         "Starter governance for IDE-attached coding agents such as Cursor and Claude Code.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"cursor", "claude-code", "langchain", "langgraph"},
		ActionSurfaces:      []string{"shell", "file", "mcp", "search", "credential"},
		Assumptions:         []string{"Developer workflow runs in shadow mode first.", "Shell access is common but high-risk commands require approval."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"read-only shell commands", "search and file-read operations", "MCP tools/call"}, Defer: []string{"file writes", "general shell execution"}, Deny: []string{"destructive shell commands"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-shell-exec", Type: "human", Timeout: "15m"}, {Rule: "defer-file-write", Type: "human", Timeout: "15m"}},
		CredentialExpect:    []hub.PackCredentialExpect{{Backend: "broker", Required: true, Scope: "coding-assistant", Note: "Broker credentials instead of ambient IDE secrets."}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe shell and write patterns."}, {Stage: "enforce", Description: "Require approvals for risky changes."}}},
		ExampleIncidents:    []string{"Destructive shell commands during repo maintenance", "Silent credential use from IDE environment"},
		Dependencies:        []string{"faramesh >= 1.0", "tool inventory store"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "bootstrap": "recommended"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"shell", "filesystem", "credentials"}, Severity: "high", BlastRadius: "developer-workspace"},
	},
	{
		Dir:                 "faramesh-mcp-server",
		Name:                "faramesh/mcp-server",
		Version:             "1.0.0",
		Description:         "Starter governance for MCP servers that expose tools over stdio or HTTP.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"mcp"},
		ActionSurfaces:      []string{"mcp", "shell", "file"},
		Assumptions:         []string{"Server exposes search/read/query style tools.", "Destructive tool calls require approval."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"tools/list", "read/query/search tool calls"}, Defer: []string{"delete/drop/destroy tool calls"}, Deny: []string{"shell usage", "system path writes"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-destructive-tools-call", Type: "human", Timeout: "10m"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "3d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "3d", Description: "Observe tool call mix."}, {Stage: "enforce", Description: "Lock shell and destructive operations."}}},
		ExampleIncidents:    []string{"Accidental destructive MCP method exposure"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"mcp_proxy": "supported"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"mcp", "shell"}, Severity: "high", BlastRadius: "served-tools"},
	},
	{
		Dir:                 "faramesh-starter",
		Name:                "faramesh/starter",
		Version:             "1.0.0",
		Description:         "Minimal getting-started pack with deny-by-default governance and a few safe permits.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"generic"},
		ActionSurfaces:      []string{"api", "search", "file", "payment"},
		Assumptions:         []string{"Teams need a small starter policy before specializing by domain."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"api/*", "search/*", "file/read/*"}, Defer: []string{"payment transfers over threshold"}, Deny: []string{"destructive shell", "system path writes"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-payment-transfer", Type: "human", Timeout: "30m"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Capture action surfaces."}, {Stage: "enforce", Description: "Convert to stricter domain pack."}}},
		ExampleIncidents:    []string{"Default-open policies with no review on sensitive actions"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"starter"}, Severity: "medium", BlastRadius: "single-agent"},
	},
	{
		Dir:                 "faramesh-payment-agent",
		Name:                "faramesh/payment-agent",
		Version:             "1.0.0",
		Description:         "Starter governance for refunds and payment-support automation.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langgraph", "langchain"},
		ActionSurfaces:      []string{"payment", "customer-data", "credential"},
		Assumptions:         []string{"Refunds above threshold require approval.", "Stripe credentials are brokered."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"customer reads", "low-value refunds", "notifications"}, Defer: []string{"high-value refunds"}, Deny: []string{"shell access"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-high-value-refund", Type: "human", Timeout: "30m", Channel: "finance"}},
		CredentialExpect:    []hub.PackCredentialExpect{{Backend: "vault", Required: true, Scope: "stripe", Note: "Use brokered payment credentials."}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe refund sizes and frequencies."}, {Stage: "enforce", Description: "Enforce finance approval thresholds."}}},
		ExampleIncidents:    []string{"Unreviewed high-value refunds", "Shell usage in payments runtime"},
		Dependencies:        []string{"faramesh >= 1.0", "credential broker"},
		Compatibility:       map[string]string{"credential_broker": "recommended"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"payments", "credentials"}, Severity: "critical", BlastRadius: "customer-funds"},
	},
	{
		Dir:                 "faramesh-support-agent",
		Name:                "faramesh/support-agent",
		Version:             "1.0.0",
		Description:         "Starter governance for customer support agents with limited credits and outbound email controls.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"generic", "langchain"},
		ActionSurfaces:      []string{"customer-data", "email", "credit", "credential"},
		Assumptions:         []string{"Low-value credits can be auto-approved.", "Mass email must be blocked."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"customer reads", "knowledge-base search", "single-recipient email", "small issue credits"}, Defer: []string{"larger issue credits"}, Deny: []string{"mass email", "shell", "filesystem"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-large-issue-credit", Type: "human", Timeout: "20m", Channel: "support-lead"}},
		CredentialExpect:    []hub.PackCredentialExpect{{Backend: "vault", Required: true, Scope: "zendesk", Note: "Support APIs should be brokered."}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe credit and email volume."}, {Stage: "enforce", Description: "Require approval above support thresholds."}}},
		ExampleIncidents:    []string{"Mass outbound email from support assistant", "Oversized credit approvals"},
		Dependencies:        []string{"faramesh >= 1.0", "credential broker"},
		Compatibility:       map[string]string{"credential_broker": "recommended"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"customer-data", "email"}, Severity: "high", BlastRadius: "customer-communications"},
	},
	{
		Dir:                 "faramesh-infra-agent",
		Name:                "faramesh/infra-agent",
		Version:             "1.0.0",
		Description:         "Starter governance for infrastructure agents that use shell and deployment tools.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"autogen", "generic"},
		ActionSurfaces:      []string{"shell", "infrastructure"},
		Assumptions:         []string{"Read-only commands are common.", "Mutation commands require approval."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"read-only shell commands"}, Defer: []string{"terraform, kubectl, docker mutations"}, Deny: []string{"destructive shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-infra-mutation", Type: "human", Timeout: "30m", Channel: "platform-team"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe mutation frequency."}, {Stage: "enforce", Description: "Require change approval for infra mutations."}}},
		ExampleIncidents:    []string{"Terraform destroy without review", "Untracked kubectl rollout restart"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"shell", "infrastructure"}, Severity: "critical", BlastRadius: "production-environment"},
	},
	{
		Dir:                 "faramesh-p2-research-agent",
		Name:                "faramesh/p2-research-agent",
		Version:             "1.0.0",
		Description:         "[P2 seed] Research-oriented agent: session/daily budgets, defer on broad HTTP, deny shell.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "langgraph", "generic"},
		ActionSurfaces:      []string{"http", "search"},
		Assumptions:         []string{"Internal and sandbox URLs are pre-approved; other HTTP defers.", "P2 packs are starting points — tighten URLs before production."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"sandbox/internal http/get"}, Defer: []string{"other http/get"}, Deny: []string{"shell/run"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-external-http", Type: "human", Timeout: "20m", Channel: "research"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe browsing patterns."}, {Stage: "enforce", Description: "Enforce URL tiers and budgets."}}},
		ExampleIncidents:    []string{"Unbounded external crawling", "Credential exfil via research tooling"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"budget_enforcement": "session_and_daily"},
		Changelog:           "P2 seed: research agent budgets and HTTP defer tiering.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"network", "cost"}, Severity: "medium", BlastRadius: "research-workspace"},
	},
	{
		Dir:                 "faramesh-p2-ops-release",
		Name:                "faramesh/p2-ops-release",
		Version:             "1.0.0",
		Description:         "[P2 seed] Release train: parallel spend caps, defer priority for prod/staging, guarded kubectl/terraform.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"generic", "langgraph"},
		ActionSurfaces:      []string{"shell", "infrastructure"},
		Assumptions:         []string{"Two release agents share an aggregate cost ceiling.", "Mutations defer; read-only kubectl/helm permit."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"read-only kubectl/helm"}, Defer: []string{"terraform/kubectl mutations"}, Deny: []string{"force destroy patterns"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-mutations", Type: "human", Timeout: "30m", Channel: "release-managers"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe parallel spend and mutation rate."}, {Stage: "enforce", Description: "Enforce aggregate caps and defer SLAs."}}},
		ExampleIncidents:    []string{"Parallel agents overspending during rollout", "Unapproved prod mutations"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"parallel_budget": "supported", "defer_priority": "supported"},
		Changelog:           "P2 seed: ops release governance with parallel budgets.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"infrastructure", "cost"}, Severity: "critical", BlastRadius: "production-release"},
	},
	{
		Dir:                 "faramesh-p2-network-controls",
		Name:                "faramesh/p2-network-controls",
		Version:             "1.0.0",
		Description:         "[P2 seed] HTTP egress defer tiering with internal permit; shell denied (browser/API agents).",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"http", "network"},
		Assumptions:         []string{"Internal hosts are glob-matched; broaden lists before production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"http/get to localhost/internal"}, Defer: []string{"other HTTP"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-external-http", Type: "human", Timeout: "20m", Channel: "security"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe outbound URLs."}, {Stage: "enforce", Description: "Enforce defer on unknown HTTP."}}},
		ExampleIncidents:    []string{"SSRF to metadata endpoints", "Unbounded crawler egress"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"proxy": "recommended", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: network egress controls.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"network", "ssrf"}, Severity: "high", BlastRadius: "egress-path"},
	},
	{
		Dir:                 "faramesh-p2-marketing-agent",
		Name:                "faramesh/p2-marketing-agent",
		Version:             "1.0.0",
		Description:         "[P2 seed] Outbound marketing: permit reads, defer bulk email, deny shell.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"http", "email"},
		Assumptions:         []string{"Campaign sends are approval-gated; HTTP reads are observable in shadow first.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"http/get for analytics and content pulls"}, Defer: []string{"email sends and bulk outbound"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-bulk-outbound", Type: "human", Timeout: "20m", Channel: "marketing-ops"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe outbound volume."}, {Stage: "enforce", Description: "Require approval on bulk email paths."}}},
		ExampleIncidents:    []string{"Unapproved blast to entire list", "Credential scraping via marketing browser"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first"},
		Changelog:           "P2 seed: marketing / outbound comms.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"email", "compliance"}, Severity: "high", BlastRadius: "customer-audiences"},
	},
	{
		Dir:                 "faramesh-p2-data-agent",
		Name:                "faramesh/p2-data-agent",
		Version:             "1.0.0",
		Description:         "[P2 seed] Analytics / data prep: search and file reads permitted; exports and external HTTP defer; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"http", "file", "search"},
		Assumptions:         []string{"Internal metrics and staging hosts are pre-listed; broaden before production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"search/*", "file/read/*", "http/get to internal metrics/staging"}, Defer: []string{"file/write exports", "other HTTP"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-exports", Type: "human", Timeout: "30m", Channel: "data-governance"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe read vs export ratio."}, {Stage: "enforce", Description: "Require approval on exports and unknown HTTP."}}},
		ExampleIncidents:    []string{"Bulk export of PII without review", "Shell-based ETL bypassing policy"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: data and analytics agent.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"data-exfiltration", "privacy"}, Severity: "high", BlastRadius: "warehouse-and-exports"},
	},
	{
		Dir:                 "faramesh-p2-customer-success",
		Name:                "faramesh/p2-customer-success",
		Version:             "1.0.0",
		Description:         "[P2 seed] Customer success: read/search and internal HTTP permitted; billing writes defer; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"customer-data", "http", "billing"},
		Assumptions:         []string{"Internal CRM/help URLs are pre-listed; expand host lists before production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"read_customer", "search_kb", "http/get to internal CRM/help"}, Defer: []string{"billing/write"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-billing-write", Type: "human", Timeout: "25m", Channel: "customer-success-lead"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe read vs billing mutation ratio."}, {Stage: "enforce", Description: "Require approval on billing writes."}}},
		ExampleIncidents:    []string{"Unauthorized plan downgrade", "Shell-based CRM scraping"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: customer success / CS playbook.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"customer-data", "billing"}, Severity: "high", BlastRadius: "customer-accounts"},
	},
	{
		Dir:                 "faramesh-p2-docs-writer",
		Name:                "faramesh/p2-docs-writer",
		Version:             "1.0.0",
		Description:         "[P2 seed] Technical writing / internal docs: search and reads permitted; publish writes defer; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"file", "search", "http"},
		Assumptions:         []string{"Internal wiki/docs hosts are pre-listed; tighten before production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"search/*", "file/read/*", "http/get to internal docs"}, Defer: []string{"file/write publishes"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-publish-write", Type: "human", Timeout: "20m", Channel: "docs-owners"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe read vs write ratio."}, {Stage: "enforce", Description: "Require approval on publish paths."}}},
		ExampleIncidents:    []string{"Overwrite of canonical runbook without review", "Shell-based doc generator exfil"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: documentation / technical writing agent.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"documentation", "integrity"}, Severity: "medium", BlastRadius: "internal-knowledge-base"},
	},
	{
		Dir:                 "faramesh-p2-webhook-agent",
		Name:                "faramesh/p2-webhook-agent",
		Version:             "1.0.0",
		Description:         "[P2 seed] Webhooks / outbound HTTP: GET permitted; POST deferred; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"http", "network"},
		Assumptions:         []string{"Callback URLs are allowlisted in production; P2 packs are templates.", "Rotate shared secrets out of policy."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"http/get"}, Defer: []string{"http/post"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-outbound-post", Type: "human", Timeout: "15m", Channel: "platform"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe outbound POST volume."}, {Stage: "enforce", Description: "Require approval on POST webhooks."}}},
		ExampleIncidents:    []string{"Unsigned webhook blast to customer systems", "Shell escape via integration runtime"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: webhook and outbound HTTP integration agent.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"network", "webhooks"}, Severity: "high", BlastRadius: "connected-systems"},
	},
	{
		Dir:                 "faramesh-p2-vendor-diligence",
		Name:                "faramesh/p2-vendor-diligence",
		Version:             "1.0.0",
		Description:         "[P2 seed] Vendor diligence: risk lookups and doc pulls permitted; contract submit defers; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"http", "vendor", "contract"},
		Assumptions:         []string{"Vendor tool IDs are illustrative — map to your CRM/CLM integrations in production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"vendor/risk_lookup", "http/get"}, Defer: []string{"vendor/contract_submit"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-contract-submit", Type: "human", Timeout: "48h", Channel: "legal"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe lookup vs submission ratio."}, {Stage: "enforce", Description: "Enforce legal approval on contract submit."}}},
		ExampleIncidents:    []string{"Unsigned vendor agreement filed", "Shell-based scraping of vendor portals"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: vendor risk and diligence workflows.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"procurement", "legal"}, Severity: "high", BlastRadius: "vendor-contracts"},
	},
	{
		Dir:                 "faramesh-p2-email-outbound",
		Name:                "faramesh/p2-email-outbound",
		Version:             "1.0.0",
		Description:         "[P2 seed] Email outbound: drafts and reads permitted; send and broadcast defer; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langchain", "generic"},
		ActionSurfaces:      []string{"email", "http"},
		Assumptions:         []string{"ESP analytics hosts are illustrative — replace with your provider URLs.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"email/draft/*", "email/read/*", "ESP analytics http/get"}, Defer: []string{"email/send/*", "email/broadcast/*"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-send", Type: "human", Timeout: "20m", Channel: "comms-ops"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "5d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "5d", Description: "Observe draft vs send ratio."}, {Stage: "enforce", Description: "Require approval on all sends."}}},
		ExampleIncidents:    []string{"Accidental blast to full customer list", "Shell-based credential harvest from mail client"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: transactional and broadcast email controls.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"email", "compliance"}, Severity: "critical", BlastRadius: "customer-inboxes"},
	},
	{
		Dir:                 "faramesh-p2-multi-agent",
		Name:                "faramesh/p2-multi-agent",
		Version:             "1.0.0",
		Description:         "[P2 seed] Multi-agent orchestration: search and internal reads permitted; delegate, spawn, and batch MCP registration defer; shell denied.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"langgraph", "langchain", "generic"},
		ActionSurfaces:      []string{"orchestration", "mcp", "http"},
		Assumptions:         []string{"Tool IDs are illustrative — align with your LangGraph / crew handoff tools in production.", "P2 packs are templates."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"search/*", "internal http/get"}, Defer: []string{"multi_agent/delegate/*", "multi_agent/spawn_worker/*", "mcp/register_tools_batch"}, Deny: []string{"shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-delegate", Type: "human", Timeout: "20m", Channel: "platform"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "7d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "7d", Description: "Observe delegation depth and fan-out."}, {Stage: "enforce", Description: "Require approval on spawn and delegate paths."}}},
		ExampleIncidents:    []string{"Runaway parallel sub-agents exhausting budget", "Unreviewed handoff to privileged tools"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"parallel_budget": "recommended", "budget_on_exceed": "defer"},
		Changelog:           "P2 seed: multi-agent coordination and fan-out governance.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"orchestration", "cost"}, Severity: "high", BlastRadius: "multi-agent-fleet"},
	},
	{
		Dir:                 "faramesh-shell-controls",
		Name:                "faramesh/shell-controls",
		Version:             "1.0.0",
		Description:         "Reusable shell safety controls for agents that need limited command execution.",
		TrustTier:           "faramesh-verified",
		SupportedFrameworks: []string{"generic"},
		ActionSurfaces:      []string{"shell"},
		Assumptions:         []string{"Shell access is permitted only for diagnostic commands by default."},
		RulesSummary:        &hub.PackRulesSummary{Permit: []string{"read-only diagnostics"}, Defer: []string{"package installs and service changes"}, Deny: []string{"destructive shell"}},
		ApprovalDefaults:    []hub.PackApprovalDefault{{Rule: "defer-shell-modification", Type: "human", Timeout: "15m"}},
		ObserveEnforce:      &hub.PackObserveEnforce{ObservePeriod: "3d", EnforcementStages: []hub.PackEnforceStage{{Stage: "shadow", Duration: "3d", Description: "Observe non-destructive shell usage."}, {Stage: "enforce", Description: "Restrict shell to approved patterns."}}},
		ExampleIncidents:    []string{"Package installation drift", "Destructive command execution"},
		Dependencies:        []string{"faramesh >= 1.0"},
		Compatibility:       map[string]string{"runtime_mode": "shadow-first"},
		Changelog:           "Initial bundled seed pack.",
		RiskModel:           &hub.PackRiskModel{Categories: []string{"shell"}, Severity: "high", BlastRadius: "host-runtime"},
	},
}

// Lookup resolves a bundled pack by name and version.
func Lookup(name, version string) (*hub.PackVersionResponse, error) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if version == "" {
		version = "latest"
	}
	for _, def := range bundledPackDefs {
		if def.Name != name {
			continue
		}
		if version != "latest" && version != def.Version {
			continue
		}
		body, err := fs.ReadFile(bundledPolicies, def.Dir+"/policy.yaml")
		if err != nil {
			return nil, fmt.Errorf("read bundled policy %s: %w", def.Dir, err)
		}
		var policyFPL string
		if fplBytes, err := fs.ReadFile(bundledPolicies, def.Dir+"/policy.fpl"); err == nil {
			policyFPL = string(fplBytes)
		}
		return &hub.PackVersionResponse{
			APIVersion:          hub.APIVersion,
			Name:                def.Name,
			Version:             def.Version,
			Description:         def.Description,
			PolicyYAML:          string(body),
			PolicyFPL:           policyFPL,
			SHA256Hex:           hub.Sum256Hex(body),
			TrustTier:           def.TrustTier,
			RiskModel:           def.RiskModel,
			SupportedFrameworks: append([]string(nil), def.SupportedFrameworks...),
			ActionSurfaces:      append([]string(nil), def.ActionSurfaces...),
			Assumptions:         append([]string(nil), def.Assumptions...),
			RulesSummary:        def.RulesSummary,
			ApprovalDefaults:    append([]hub.PackApprovalDefault(nil), def.ApprovalDefaults...),
			CredentialExpect:    append([]hub.PackCredentialExpect(nil), def.CredentialExpect...),
			ObserveEnforce:      def.ObserveEnforce,
			ExampleIncidents:    append([]string(nil), def.ExampleIncidents...),
			Dependencies:        append([]string(nil), def.Dependencies...),
			FarameshVersion:     "1.0",
			Compatibility:       cloneMap(def.Compatibility),
			Changelog:           def.Changelog,
		}, nil
	}
	return nil, fmt.Errorf("bundled pack not found: %s@%s", name, version)
}

// Search returns bundled pack summaries matching the query.
func Search(query string) []hub.PackSummary {
	query = strings.ToLower(strings.TrimSpace(query))
	out := make([]hub.PackSummary, 0, len(bundledPackDefs))
	for _, def := range bundledPackDefs {
		if query != "" &&
			!strings.Contains(strings.ToLower(def.Name), query) &&
			!strings.Contains(strings.ToLower(def.Description), query) {
			continue
		}
		out = append(out, hub.PackSummary{
			Name:          def.Name,
			LatestVersion: def.Version,
			Description:   def.Description,
			Downloads:     0,
			TrustTier:     def.TrustTier,
		})
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
