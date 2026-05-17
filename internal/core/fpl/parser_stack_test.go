package fpl

import "testing"

func TestParseDocumentStackBlocks(t *testing.T) {
	src := `
import "registry.faramesh.dev/frameworks/langgraph@1.0.0"

runtime {
  mode = enforce
  wal_dir = "./faramesh-wal"
  backend = sqlite
}

provider "vault" {
  type = vault
  addr = env("VAULT_ADDR")
}

agent "my-app-agent" {
  default deny
  rules {
    defer search_docs
  }
}
`
	doc, err := ParseDocument(src)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if len(doc.Imports) != 1 || doc.Imports[0].Ref == "" {
		t.Fatalf("imports: %+v", doc.Imports)
	}
	if doc.Runtime == nil || doc.Runtime.Fields["mode"].String != "enforce" {
		t.Fatalf("runtime: %+v", doc.Runtime)
	}
	if len(doc.Providers) != 1 {
		t.Fatalf("providers: %+v", doc.Providers)
	}
	if doc.Providers[0].Fields["addr"].Kind != ConfigEnv || doc.Providers[0].Fields["addr"].EnvVar != "VAULT_ADDR" {
		t.Fatalf("env call: %+v", doc.Providers[0].Fields["addr"])
	}
	if len(doc.Agents) != 1 || doc.Agents[0].ID != "my-app-agent" {
		t.Fatalf("agents: %+v", doc.Agents)
	}
}
