package credential

import (
	"context"
	"reflect"
	"testing"
)

type testBroker struct {
	name string
}

func (b *testBroker) Name() string { return b.name }

func (b *testBroker) Fetch(_ context.Context, _ FetchRequest) (*Credential, error) {
	return &Credential{Source: b.name}, nil
}

func (b *testBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

func TestRouterResolveRouteUsesMostSpecificMatch(t *testing.T) {
	env := &testBroker{name: "env"}
	vault := &testBroker{name: "vault"}
	r := NewRouter([]Broker{env, vault}, env)
	if err := r.AddRoute("*", "env"); err != nil {
		t.Fatalf("add wildcard route: %v", err)
	}
	if err := r.AddRoute("stripe/*", "vault"); err != nil {
		t.Fatalf("add stripe route: %v", err)
	}

	resolved := r.ResolveRoute("stripe/refund")
	if resolved.Pattern != "stripe/*" {
		t.Fatalf("pattern=%q want stripe/*", resolved.Pattern)
	}
	if resolved.Backend != "vault" {
		t.Fatalf("backend=%q want vault", resolved.Backend)
	}
	if resolved.UsedFallback {
		t.Fatalf("expected matched route, got fallback=true")
	}

	resolved = r.ResolveRoute("db/query")
	if resolved.Pattern != "*" {
		t.Fatalf("pattern=%q want *", resolved.Pattern)
	}
	if resolved.Backend != "env" {
		t.Fatalf("backend=%q want env", resolved.Backend)
	}
}

func TestRouterSnapshotAccessors(t *testing.T) {
	env := &testBroker{name: "env"}
	vault := &testBroker{name: "vault"}
	r := NewRouter([]Broker{vault, env}, env)
	if err := r.AddRoute("*", "env"); err != nil {
		t.Fatalf("add wildcard route: %v", err)
	}
	if err := r.AddRoute("stripe/*", "vault"); err != nil {
		t.Fatalf("add stripe route: %v", err)
	}

	names := r.BackendNames()
	if !reflect.DeepEqual(names, []string{"env", "vault"}) {
		t.Fatalf("backend names=%v", names)
	}
	if got := r.FallbackBackendName(); got != "env" {
		t.Fatalf("fallback backend=%q want env", got)
	}

	routes := r.RoutesSnapshot()
	if len(routes) != 2 {
		t.Fatalf("routes len=%d want 2", len(routes))
	}
	routes["new/*"] = "env"
	if len(r.RoutesSnapshot()) != 2 {
		t.Fatalf("routes snapshot should be copy")
	}
}
