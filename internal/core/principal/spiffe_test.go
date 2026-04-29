package principal

import (
	"context"
	"errors"
	"testing"
)

func TestSPIFFEProviderIdentityUsesConfiguredResolver(t *testing.T) {
	p := NewSPIFFEProvider("/tmp/spire-agent.sock")
	p.resolveID = func(_ context.Context, socketPath string) (string, error) {
		if socketPath != "/tmp/spire-agent.sock" {
			t.Fatalf("socket path = %q, want /tmp/spire-agent.sock", socketPath)
		}
		return "spiffe://example.org/ns/prod/sa/faramesh", nil
	}

	identity, err := p.Identity(context.Background())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if identity == nil {
		t.Fatalf("expected identity")
	}
	if identity.ID != "spiffe://example.org/ns/prod/sa/faramesh" {
		t.Fatalf("identity id = %q", identity.ID)
	}
	if identity.Org != "example.org" {
		t.Fatalf("identity org = %q, want example.org", identity.Org)
	}
	if !identity.Verified || identity.Method != "spiffe" {
		t.Fatalf("unexpected identity flags: %+v", identity)
	}
}

func TestSPIFFEProviderIdentityPropagatesResolverError(t *testing.T) {
	p := NewSPIFFEProvider("/tmp/spire-agent.sock")
	p.resolveID = func(context.Context, string) (string, error) {
		return "", errors.New("workload api unavailable")
	}

	_, err := p.Identity(context.Background())
	if err == nil || err.Error() != "workload api unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExplicitSPIFFEIDPrefersEnvironmentOverride(t *testing.T) {
	t.Setenv("FARAMESH_SPIFFE_ID", "spiffe://env.example/agent/test")

	got, ok := explicitSPIFFEID()
	if !ok {
		t.Fatalf("expected explicit SPIFFE ID override")
	}
	if got != "spiffe://env.example/agent/test" {
		t.Fatalf("explicit SPIFFE ID = %q", got)
	}
}

func TestNormalizeSPIFFESocketAddr(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "/tmp/spire-agent.sock", want: "unix:///tmp/spire-agent.sock"},
		{in: "unix:///tmp/spire-agent.sock", want: "unix:///tmp/spire-agent.sock"},
		{in: "unix:/tmp/spire-agent.sock", want: "unix:///tmp/spire-agent.sock"},
		{in: "tcp://127.0.0.1:8081", want: "tcp://127.0.0.1:8081"},
	}

	for _, tt := range tests {
		if got := normalizeSPIFFESocketAddr(tt.in); got != tt.want {
			t.Fatalf("normalizeSPIFFESocketAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
