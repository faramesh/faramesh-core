package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
)

func TestBuildRunEnv_nonEmptyCore(t *testing.T) {
	d := &runtimeenv.DetectedEnvironment{
		TrustLevel:   "linux_user_land",
		AdapterLevel: 1,
		Runtime:      "local",
		Framework:    "langchain",
	}
	e := buildRunEnv(d, "")
	s := strings.Join(e, " ")
	if !strings.Contains(s, "FARAMESH_SPAWNED_BY=faramesh-run") || !strings.Contains(s, "FARAMESH_TRUST_LEVEL=") {
		t.Fatal(s)
	}
}

func TestMergeEnv_override(t *testing.T) {
	base := []string{"FOO=1", "FARAMESH_TRUST_LEVEL=old"}
	extra := []string{"FARAMESH_TRUST_LEVEL=new"}
	out := mergeEnv(base, extra)
	if strings.Join(out, ";") != "FOO=1;FARAMESH_TRUST_LEVEL=new" {
		t.Fatalf("%v", out)
	}
}

func TestRunCmdJSON(t *testing.T) {
	root := findRepoRoot(t)
	cmd := exec.Command("go", "run", ".", "run", "--json")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v", err)
	}
	var d runtimeenv.DetectedEnvironment
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if d.Runtime == "" || d.GoOS == "" {
		t.Fatalf("%+v", d)
	}
}

func TestStripAmbientCredentials(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/test",
		"OPENAI_API_KEY=sk-abc123",
		"STRIPE_API_KEY=sk_live_456",
		"FARAMESH_SOCKET=/tmp/faramesh.sock",
		"DATABASE_URL=postgres://localhost:5432/db",
		"MY_CUSTOM_VAR=keep",
	}
	out, stripped := stripAmbientCredentials(env)

	if len(stripped) != 3 {
		t.Fatalf("expected 3 stripped, got %d: %v", len(stripped), stripped)
	}
	for _, s := range stripped {
		if s != "OPENAI_API_KEY" && s != "STRIPE_API_KEY" && s != "DATABASE_URL" {
			t.Fatalf("unexpected strip: %s", s)
		}
	}

	for _, e := range out {
		k, _, _ := strings.Cut(e, "=")
		if k == "OPENAI_API_KEY" || k == "STRIPE_API_KEY" || k == "DATABASE_URL" {
			t.Fatalf("should have been stripped: %s", e)
		}
	}

	found := false
	for _, e := range out {
		if strings.HasPrefix(e, "MY_CUSTOM_VAR=") {
			found = true
		}
	}
	if !found {
		t.Fatal("MY_CUSTOM_VAR should be preserved")
	}
}

func TestEnforcementReport_trustLevel(t *testing.T) {
	r := &enforcementReport{
		autoload:       true,
		credentialStrip: []string{"OPENAI_API_KEY"},
	}
	// Without OS layers, trust level stays as whatever was passed
	if r.trustLevel != "" {
		t.Fatalf("expected empty trust level before enforcement, got %q", r.trustLevel)
	}
}

func TestShouldEnforce(t *testing.T) {
	if shouldEnforce("none") {
		t.Fatal("none should not enforce")
	}
	if !shouldEnforce("auto") {
		t.Fatal("auto should enforce")
	}
	if !shouldEnforce("full") {
		t.Fatal("full should enforce")
	}
}
