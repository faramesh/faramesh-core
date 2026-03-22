package core

import (
	"os"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func TestPipeline_varsDeploymentKindInWhen(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "a1"
default_effect: deny
rules:
  - id: k8s-only-http
    match:
      tool: "http/get"
      when: vars.deployment_kind == "kubernetes"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	prev := os.Getenv("KUBERNETES_SERVICE_HOST")
	defer func() { _ = os.Setenv("KUBERNETES_SERVICE_HOST", prev) }()
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")

	d0 := p.Evaluate(CanonicalActionRequest{
		CallID:    "c0",
		AgentID:   "a1",
		SessionID: "s",
		ToolID:    "http/get",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d0.Effect != EffectDeny {
		t.Fatalf("without k8s expected deny, got %v", d0.Effect)
	}

	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	d1 := p.Evaluate(CanonicalActionRequest{
		CallID:    "c1",
		AgentID:   "a1",
		SessionID: "s",
		ToolID:    "http/get",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d1.Effect != EffectPermit {
		t.Fatalf("with k8s expected permit, got %v %+v", d1.Effect, d1)
	}
}

func TestPipeline_varsRegionInWhen(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "a1"
default_effect: deny
rules:
  - id: eu-only
    match:
      tool: "http/get"
      when: vars.region == "eu-central-1"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	prev := os.Getenv("FARAMESH_REGION")
	defer func() { _ = os.Setenv("FARAMESH_REGION", prev) }()
	_ = os.Unsetenv("FARAMESH_REGION")
	_ = os.Unsetenv("AWS_REGION")

	if d := p.Evaluate(CanonicalActionRequest{
		CallID: "r0", AgentID: "a1", SessionID: "s", ToolID: "http/get", Args: map[string]any{}, Timestamp: time.Now(),
	}); d.Effect != EffectDeny {
		t.Fatalf("expected deny without region")
	}

	_ = os.Setenv("FARAMESH_REGION", "eu-central-1")
	if d := p.Evaluate(CanonicalActionRequest{
		CallID: "r1", AgentID: "a1", SessionID: "s", ToolID: "http/get", Args: map[string]any{}, Timestamp: time.Now(),
	}); d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %+v", d)
	}
}

func TestPipeline_varsK8sNamespaceInWhen(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "a1"
default_effect: deny
rules:
  - id: ns-prod
    match:
      tool: "http/get"
      when: vars.k8s_namespace == "production"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	prev := map[string]string{
		"POD_NAMESPACE":          os.Getenv("POD_NAMESPACE"),
		"FARAMESH_K8S_NAMESPACE": os.Getenv("FARAMESH_K8S_NAMESPACE"),
	}
	defer func() {
		for k, v := range prev {
			_ = os.Setenv(k, v)
		}
	}()
	_ = os.Unsetenv("POD_NAMESPACE")
	_ = os.Unsetenv("FARAMESH_K8S_NAMESPACE")
	_ = os.Unsetenv("K8S_NAMESPACE")

	if d := p.Evaluate(CanonicalActionRequest{
		CallID: "n0", AgentID: "a1", SessionID: "s", ToolID: "http/get", Args: map[string]any{}, Timestamp: time.Now(),
	}); d.Effect != EffectDeny {
		t.Fatalf("expected deny without namespace")
	}
	_ = os.Setenv("POD_NAMESPACE", "production")
	if d := p.Evaluate(CanonicalActionRequest{
		CallID: "n1", AgentID: "a1", SessionID: "s", ToolID: "http/get", Args: map[string]any{}, Timestamp: time.Now(),
	}); d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %+v", d)
	}
}

func TestPipeline_varsFarameshVersionInWhen(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "a1"
default_effect: deny
rules:
  - id: version-guard
    match:
      tool: "http/get"
      when: vars.faramesh_version != "__sentinel_never__"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	if d := p.Evaluate(CanonicalActionRequest{
		CallID: "v0", AgentID: "a1", SessionID: "s", ToolID: "http/get", Args: map[string]any{}, Timestamp: time.Now(),
	}); d.Effect != EffectPermit {
		t.Fatalf("expected permit when faramesh_version is set, got %+v", d)
	}
}
