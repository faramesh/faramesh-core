package policy

import (
	"path/filepath"
	"testing"
)

func TestPolicyLoader_FromString_FPLInline(t *testing.T) {
	pl := NewPolicyLoader()
	yaml := `
faramesh-version: "1.0"
agent-id: "pl-test"
default_effect: deny
rules:
  - id: base
    match: { tool: "x", when: "true" }
    effect: deny
fpl_inline: |
  permit fpl/tool when true
`
	src, err := pl.FromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Doc.Rules) != 2 {
		t.Fatalf("rules %d", len(src.Doc.Rules))
	}
	if src.Doc.Rules[1].Match.Tool != "fpl/tool" {
		t.Fatalf("fpl rule: %+v", src.Doc.Rules[1])
	}
}

func TestPolicyLoader_FromFile_FPLFiles(t *testing.T) {
	pl := NewPolicyLoader()
	p := filepath.Join("testdata", "policy_with_fpl_files.yaml")
	src, err := pl.FromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Doc.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(src.Doc.Rules))
	}
	if src.Doc.Rules[1].Match.Tool != "overlay/tool" {
		t.Fatalf("overlay: %+v", src.Doc.Rules[1])
	}
}

func TestPolicyLoader_FromURL_rejectsFPLFiles(t *testing.T) {
	pl := NewPolicyLoader()
	// httptest server would need to serve yaml with fpl_files — exercise loadFromData path with empty dir
	_, err := pl.loadFromData([]byte(`faramesh-version: "1.0"
agent-id: "t"
default_effect: deny
fpl_files: [x.fpl]
`), SourceURL, "http://example/p.yaml", "")
	if err == nil {
		t.Fatal("expected error for fpl_files without policy directory")
	}
}

func TestLoadFPLDocument_MapsCredentialBlocksToToolTags(t *testing.T) {
	fplSrc := `
agent cred-test {
  default deny

  credential vault_probe {
    scope vault/probe
    backend vault
    max_scope payments
  }

  rules {
    permit vault/probe
  }
}
`

	doc, _, err := loadFPLDocument([]byte(fplSrc))
	if err != nil {
		t.Fatalf("loadFPLDocument error: %v", err)
	}
	tool, ok := doc.Tools["vault/probe"]
	if !ok {
		t.Fatalf("expected tool metadata for vault/probe")
	}
	requiredTags := []string{"credential:broker", "credential:required", "credential:scope:payments"}
	for _, required := range requiredTags {
		found := false
		for _, actual := range tool.Tags {
			if actual == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing tag %q in %+v", required, tool.Tags)
		}
	}
}

func TestLoadFPLDocument_CredentialScopeShorthandExpandsToNamespace(t *testing.T) {
	fplSrc := `
agent cred-test {
  default deny

  credential stripe {
    scope refund
    backend vault
    ttl 15m
		max_scope "refund:amount<=1000"
  }

  rules {
    permit stripe/refund
  }
}
`

	doc, _, err := loadFPLDocument([]byte(fplSrc))
	if err != nil {
		t.Fatalf("loadFPLDocument error: %v", err)
	}
	tool, ok := doc.Tools["stripe/refund"]
	if !ok {
		t.Fatalf("expected tool metadata for stripe/refund")
	}
	required := []string{
		"credential:broker",
		"credential:required",
		"credential:backend:vault",
		"credential:ttl:15m",
		"credential:scope:refund:amount<=1000",
	}
	for _, tag := range required {
		found := false
		for _, actual := range tool.Tags {
			if actual == tag {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing tag %q in %+v", tag, tool.Tags)
		}
	}
}

func TestLoadFPLDocument_PreservesRuleNotifyTarget(t *testing.T) {
	fplSrc := `
agent notify-test {
  default deny
  rules {
    defer stripe/refund when amount > 500 notify: "finance" reason: "high value"
  }
}
`

	doc, _, err := loadFPLDocument([]byte(fplSrc))
	if err != nil {
		t.Fatalf("loadFPLDocument error: %v", err)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(doc.Rules))
	}
	if doc.Rules[0].Notify != "finance" {
		t.Fatalf("expected notify target finance, got %q", doc.Rules[0].Notify)
	}
}

func TestLoadFPLDocument_LowersDelegateAmbientSelectorBlocks(t *testing.T) {
	fplSrc := `
agent runtime-bridge {
  default deny
  delegate approval-worker {
    scope "stripe/refund"
    ttl 1h
    ceiling approval
  }
  ambient {
    max_calls_per_day 10
    max_customers_per_day 5
    max_data_volume 10mb
    on_exceed defer
  }
  selector customer-ledger {
    source "https://ctx.example.local/customer-ledger"
    cache 30s
    on_unavailable deny
    on_timeout defer
  }
  rules {
    permit invoke_agent
  }
}
`

	doc, _, err := loadFPLDocument([]byte(fplSrc))
	if err != nil {
		t.Fatalf("loadFPLDocument error: %v", err)
	}
	if doc.OrchestratorManifest == nil {
		t.Fatal("expected orchestrator manifest from delegate block")
	}
	if doc.OrchestratorManifest.AgentID != "runtime-bridge" {
		t.Fatalf("unexpected orchestrator id %q", doc.OrchestratorManifest.AgentID)
	}
	if len(doc.OrchestratorManifest.PermittedInvocations) != 1 {
		t.Fatalf("expected 1 delegated target, got %+v", doc.OrchestratorManifest.PermittedInvocations)
	}
	invocation := doc.OrchestratorManifest.PermittedInvocations[0]
	if invocation.AgentID != "approval-worker" {
		t.Fatalf("unexpected delegated agent %q", invocation.AgentID)
	}
	if !invocation.RequiresPriorApproval {
		t.Fatal("expected delegate ceiling approval to require prior approval")
	}
	if len(doc.DelegationPolicies) != 1 {
		t.Fatalf("expected 1 delegation policy, got %+v", doc.DelegationPolicies)
	}
	delegation := doc.DelegationPolicies[0]
	if delegation.TargetAgent != "approval-worker" {
		t.Fatalf("unexpected delegation target %q", delegation.TargetAgent)
	}
	if delegation.Scope != "stripe/refund" || delegation.TTL != "1h" || delegation.Ceiling != "approval" {
		t.Fatalf("unexpected delegation policy %+v", delegation)
	}

	if len(doc.ContextGuards) != 1 {
		t.Fatalf("expected selector to lower into 1 context guard, got %d", len(doc.ContextGuards))
	}
	guard := doc.ContextGuards[0]
	if guard.Source != "customer-ledger" || guard.Endpoint != "https://ctx.example.local/customer-ledger" {
		t.Fatalf("unexpected selector lowering %+v", guard)
	}
	if guard.MaxAgeSecs != 30 {
		t.Fatalf("expected selector cache 30s to map to max_age_seconds=30, got %d", guard.MaxAgeSecs)
	}
	if guard.OnMissing != "deny" || guard.OnStale != "defer" {
		t.Fatalf("unexpected selector failure mapping on_missing=%q on_stale=%q", guard.OnMissing, guard.OnStale)
	}

	if len(doc.CrossSessionGuards) != 3 {
		t.Fatalf("expected 3 cross-session guards, got %d", len(doc.CrossSessionGuards))
	}
	metrics := map[string]int{}
	for _, g := range doc.CrossSessionGuards {
		metrics[g.Metric] = g.MaxUniqueRecords
		if g.Scope != "principal" {
			t.Fatalf("expected principal scope guard, got %+v", g)
		}
		if g.OnExceed != "defer" {
			t.Fatalf("expected on_exceed defer, got %+v", g)
		}
	}
	if metrics["call_count"] != 10 {
		t.Fatalf("expected call_count limit 10, got %d", metrics["call_count"])
	}
	if metrics["unique_record_count"] != 5 {
		t.Fatalf("expected unique_record_count limit 5, got %d", metrics["unique_record_count"])
	}
	if metrics["data_volume_bytes"] != 10*1024*1024 {
		t.Fatalf("expected data_volume_bytes limit %d, got %d", 10*1024*1024, metrics["data_volume_bytes"])
	}
}
