package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const credentialPolicy = `
faramesh-version: "1.0"
agent-id: "credential-agent"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

type captureWAL struct {
	last *dpr.Record
}

func (w *captureWAL) Write(rec *dpr.Record) error {
	w.last = rec
	return nil
}
func (w *captureWAL) Close() error { return nil }

type fakeBroker struct {
	name  string
	cred  *credential.Credential
	err   error
	calls int
}

func (b *fakeBroker) Name() string { return b.name }
func (b *fakeBroker) Fetch(_ context.Context, _ credential.FetchRequest) (*credential.Credential, error) {
	b.calls++
	if b.err != nil {
		return nil, b.err
	}
	return b.cred, nil
}
func (b *fakeBroker) Revoke(_ context.Context, _ *credential.Credential) error { return nil }

func buildCredentialPipeline(t *testing.T, broker credential.Broker, wal dpr.Writer) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(credentialPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	router := credential.NewRouter([]credential.Broker{broker}, broker)
	if err := router.AddRoute("*", broker.Name()); err != nil {
		t.Fatalf("add route: %v", err)
	}
	return NewPipeline(Config{
		Engine:           policy.NewAtomicEngine(eng),
		WAL:              wal,
		Sessions:         session.NewManager(),
		Defers:           deferwork.NewWorkflow(""),
		CredentialRouter: router,
	})
}

func TestCredentialBrokerSuccessPopulatesDPRFields(t *testing.T) {
	wal := &captureWAL{}
	b := &fakeBroker{
		name: "fake",
		cred: &credential.Credential{
			Value:  "tok_123",
			Source: "fake",
			Scope:  "payments:write",
		},
	}
	p := buildCredentialPipeline(t, b, wal)
	args := map[string]any{}
	args["_credential_broker"] = true
	args["_credential_required"] = true
	args["_credential_scope"] = "payments:write"
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cred-success",
		AgentID:   "agent-cred",
		SessionID: "sess-cred",
		ToolID:    "credential/tool",
		Args:      args,
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}
	if b.calls != 1 {
		t.Fatalf("expected broker fetch exactly once, got %d", b.calls)
	}
	if wal.last == nil {
		t.Fatalf("expected DPR record")
	}
	if got := boolRecordField(wal.last, "CredentialBrokered"); !got {
		t.Fatalf("expected credential_brokered=true in DPR record")
	}
	if got := stringRecordField(wal.last, "CredentialSource"); got != "fake" {
		t.Fatalf("expected credential_source=fake, got %q", got)
	}
	if got := stringRecordField(wal.last, "CredentialScope"); got != "payments:write" {
		t.Fatalf("expected credential_scope=payments:write, got %q", got)
	}
}

func TestCredentialBrokerErrorFailsClosedWhenRequired(t *testing.T) {
	wal := &captureWAL{}
	b := &fakeBroker{name: "fake", err: errors.New("backend unavailable")}
	p := buildCredentialPipeline(t, b, wal)
	args := map[string]any{}
	args["_credential_broker"] = true
	args["_credential_required"] = true
	args["_credential_scope"] = "payments:write"
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cred-fail",
		AgentID:   "agent-cred",
		SessionID: "sess-cred",
		ToolID:    "credential/tool",
		Args:      args,
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny fail-safe on required broker error, got %s", d.Effect)
	}
}

func TestCredentialBrokerNonBrokerToolUnchanged(t *testing.T) {
	wal := &captureWAL{}
	b := &fakeBroker{
		name: "fake",
		cred: &credential.Credential{Value: "tok_123", Source: "fake", Scope: "payments:write"},
	}
	p := buildCredentialPipeline(t, b, wal)
	args := map[string]any{"foo": "bar"}
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cred-non-broker",
		AgentID:   "agent-cred",
		SessionID: "sess-cred",
		ToolID:    "safe/read",
		Args:      args,
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}
	if _, ok := args["_faramesh"]; ok {
		t.Fatalf("non-broker tool args should remain unchanged")
	}
	if b.calls != 0 {
		t.Fatalf("non-broker tool should not call broker")
	}
}

func boolRecordField(rec *dpr.Record, field string) bool {
	v := reflect.Indirect(reflect.ValueOf(rec))
	f := v.FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return false
	}
	return f.Bool()
}

func stringRecordField(rec *dpr.Record, field string) string {
	v := reflect.Indirect(reflect.ValueOf(rec))
	f := v.FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}
