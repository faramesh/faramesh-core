package governance

import (
	"os"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

func TestCheckImportLatest(t *testing.T) {
	doc := &ast.Document{
		SourcePath: "governance.fms",
		Imports:    []ast.Import{{Ref: "registry.faramesh.dev/frameworks/x@latest", Line: 1}},
		Agents: map[string]*ast.Agent{
			"a": {Name: "a", Rules: []ast.Rule{{Effect: "defer", Tool: "t"}}},
		},
	}
	diags := Check(doc, CheckOptions{})
	if !HasErrors(diags) {
		t.Fatal("expected error for @latest import")
	}
}

func TestCheckCredentialBackend(t *testing.T) {
	doc := &ast.Document{
		SourcePath: "governance.fms",
		Agents: map[string]*ast.Agent{
			"bot": {
				Name: "bot",
				Credentials: []ast.Credential{
					{Name: "stripe", Backend: "vault"},
				},
				Rules: []ast.Rule{{Effect: "defer", Tool: "pay"}},
			},
		},
	}
	diags := Check(doc, CheckOptions{})
	if !HasErrors(diags) {
		t.Fatal("expected missing provider error")
	}
}

func TestCheckEnvUnset(t *testing.T) {
	_ = os.Unsetenv("FARAMESH_TEST_GOV_VAR_XYZ")
	doc := &ast.Document{
		SourcePath: "governance.fms",
		Providers: map[string]*ast.Provider{
			"vault": {
				Name: "vault", Type: "vault",
				Config: map[string]ast.Value{
					"addr": ast.EnvValue("FARAMESH_TEST_GOV_VAR_XYZ"),
				},
			},
		},
		Agents: map[string]*ast.Agent{
			"a": {Name: "a", Rules: []ast.Rule{{Effect: "defer", Tool: "t"}}},
		},
	}
	diags := Check(doc, CheckOptions{RequireEnv: true})
	if !HasErrors(diags) {
		t.Fatal("expected unset env error")
	}
}
