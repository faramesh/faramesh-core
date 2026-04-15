package main

import (
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

func TestRunSuggestYAML(t *testing.T) {
	dir := t.TempDir()
	store, err := toolinventory.OpenStore(dir + "/faramesh-tool-inventory.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.RecordObservation(toolinventory.Observation{
		ToolID:       "search/web",
		Effect:       "PERMIT",
		CoverageTier: "A",
		Timestamp:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record observation: %v", err)
	}

	out, err := runSuggest(suggestOptions{
		DataDir: dir,
		AgentID: "starter",
		Format:  "yaml",
		Now:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("runSuggest: %v", err)
	}
	if !strings.Contains(string(out), "agent-id: starter") {
		t.Fatalf("expected YAML output to include agent-id, got:\n%s", string(out))
	}
	if !strings.Contains(string(out), "tool: search/web") {
		t.Fatalf("expected YAML output to include search/web rule, got:\n%s", string(out))
	}
}

func TestRunSuggestJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := toolinventory.OpenStore(dir + "/faramesh-tool-inventory.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.RecordObservation(toolinventory.Observation{
		ToolID:       "credential/fetch",
		Effect:       "PERMIT",
		CoverageTier: "A",
		Timestamp:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record observation: %v", err)
	}

	out, err := runSuggest(suggestOptions{
		DataDir: dir,
		Format:  "json",
		Now:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("runSuggest: %v", err)
	}
	if !strings.Contains(string(out), `"tool_id": "credential/fetch"`) {
		t.Fatalf("expected JSON output to include recommendation, got:\n%s", string(out))
	}
	if !strings.Contains(string(out), `"effect": "defer"`) {
		t.Fatalf("expected JSON output to include defer recommendation, got:\n%s", string(out))
	}
}
