package principal

import (
	"context"
	"testing"
)

func TestDetectWorkloadProviderPrefersSPIFFEIDOverride(t *testing.T) {
	t.Setenv("FARAMESH_SPIFFE_SOCKET_PATH", "")
	t.Setenv("FARAMESH_SPIFFE_ID", "spiffe://example.org/agent/test")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GCE_METADATA_HOST", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("MSI_ENDPOINT", "")
	t.Setenv("GITHUB_ACTIONS", "")

	provider := DetectWorkloadProvider()
	if provider == nil {
		t.Fatalf("expected workload provider when FARAMESH_SPIFFE_ID is set")
	}
	if provider.Name() != "spiffe" {
		t.Fatalf("expected spiffe provider, got %q", provider.Name())
	}

	ctx := context.Background()
	if !provider.Available(ctx) {
		t.Fatalf("expected spiffe provider to be available with explicit SPIFFE ID")
	}
	identity, err := provider.Identity(ctx)
	if err != nil {
		t.Fatalf("resolve spiffe identity: %v", err)
	}
	if identity == nil || identity.ID != "spiffe://example.org/agent/test" {
		t.Fatalf("unexpected identity resolved: %+v", identity)
	}
}
