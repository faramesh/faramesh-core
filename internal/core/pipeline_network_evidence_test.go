package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const policyNetworkEvidencePermit = `
faramesh-version: "1.0"
agent-id: "network-evidence-agent"
default_effect: deny
rules:
  - id: allow-network
    match:
      tool: "proxy/http"
    effect: permit
`

func TestBuildRecordIncludesNetworkEvidence(t *testing.T) {
	wal := &captureWAL{}
	doc, ver, err := policy.LoadBytes([]byte(policyNetworkEvidencePermit))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		WAL:      wal,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "net-evidence-1",
		AgentID:   "agent-network",
		SessionID: "sess-network",
		ToolID:    "proxy/http",
		Args: map[string]any{
			"hardening_mode": "enforce",
			"host":           "api.example.com",
			"port":           443,
			"resolved_ip":    "198.51.100.25",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s", d.Effect)
	}
	if wal.last == nil {
		t.Fatal("expected DPR record to be written")
	}
	if wal.last.HardeningMode != "enforce" {
		t.Fatalf("expected hardening mode enforce, got %q", wal.last.HardeningMode)
	}
	if wal.last.NetworkPort != 443 {
		t.Fatalf("expected network port 443, got %d", wal.last.NetworkPort)
	}
	if wal.last.NetworkHostHash == "" {
		t.Fatal("expected network host hash to be set")
	}
	if wal.last.NetworkResolvedIPHash == "" {
		t.Fatal("expected network resolved IP hash to be set")
	}
	if wal.last.NetworkAuditBypass {
		t.Fatal("expected network audit bypass to be false")
	}
}

func TestBuildRecordMarksNetworkAuditBypass(t *testing.T) {
	wal := &captureWAL{}
	policyDoc := `
faramesh-version: "1.0"
agent-id: "audit-bypass-agent"
default_effect: deny
rules:
  - id: permit-audit-reason
    match:
      tool: "proxy/connect"
    effect: permit
    reason_code: NETWORK_L7_AUDIT_VIOLATION
`
	doc, ver, err := policy.LoadBytes([]byte(policyDoc))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		WAL:      wal,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "net-audit-1",
		AgentID:   "agent-network",
		SessionID: "sess-network",
		ToolID:    "proxy/connect",
		Args: map[string]any{
			"hardening_mode": "audit",
			"host":           "example.com",
			"port":           443,
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.NetworkL7AuditViolation {
		t.Fatalf("expected reason code %s, got %s", reasons.NetworkL7AuditViolation, d.ReasonCode)
	}
	if wal.last == nil {
		t.Fatal("expected DPR record to be written")
	}
	if !wal.last.NetworkAuditBypass {
		t.Fatal("expected network audit bypass to be true")
	}
}
