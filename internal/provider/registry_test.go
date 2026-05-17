package provider

import (
	"context"
	"testing"
)

func TestRegistryBuiltinVaultDryRun(t *testing.T) {
	reg := NewRegistry("")
	spec := Spec{
		Name: "vault",
		Type: "vault",
		Config: map[string]string{
			"addr":  "http://127.0.0.1:8200",
			"token": "test-token",
		},
	}
	if err := reg.Register(spec); err != nil {
		t.Fatal(err)
	}
	if err := reg.InitAll(context.Background(), true); err != nil {
		t.Fatalf("InitAll dry-run: %v", err)
	}
	router := reg.CredentialRouter()
	if router == nil {
		t.Fatal("expected credential router")
	}
	_ = reg.Close(context.Background())
}
