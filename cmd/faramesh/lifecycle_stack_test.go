package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseStackServiceMode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want stackServiceMode
		err  bool
	}{
		{name: "default auto", in: "", want: stackServiceModeAuto},
		{name: "auto", in: "auto", want: stackServiceModeAuto},
		{name: "on", in: "on", want: stackServiceModeOn},
		{name: "off", in: "off", want: stackServiceModeOff},
		{name: "invalid", in: "maybe", err: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStackServiceMode(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("parseStackServiceMode(%q) expected error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStackServiceMode(%q) err=%v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseStackServiceMode(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAsBool(t *testing.T) {
	if !asBool(true, false) {
		t.Fatal("expected true for boolean true")
	}
	if asBool(false, true) {
		t.Fatal("expected false for boolean false")
	}
	if !asBool("yes", false) {
		t.Fatal("expected true for yes")
	}
	if asBool("off", true) {
		t.Fatal("expected false for off")
	}
	if got := asBool("unknown", true); !got {
		t.Fatal("expected fallback true for unknown string")
	}
}

func TestResolveServiceDirPrefersExplicit(t *testing.T) {
	explicit := t.TempDir()
	cwd := t.TempDir()
	resolved := resolveServiceDir(cwd, explicit, "FARAMESH_TEST_SERVICE_DIR", []string{"missing/suffix"})
	if resolved != explicit {
		t.Fatalf("resolveServiceDir returned %q, want explicit %q", resolved, explicit)
	}
}

func TestResolveServiceDirUsesCWDRelativeCandidatesOnly(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	target := filepath.Join(root, "visibility-server")

	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	if found := resolveServiceDir(nested, "", "", []string{"visibility-server"}); found != "" {
		t.Fatalf("expected no parent traversal; got %q", found)
	}

	if found := resolveServiceDir(root, "", "", []string{"visibility-server"}); found != target {
		t.Fatalf("expected cwd-relative discovery %q, got %q", target, found)
	}
}
