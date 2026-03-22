package hub

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePackToDisk(t *testing.T) {
	dir := t.TempDir()
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"t\"\n",
		TrustTier:  "verified",
	}
	path, err := WritePackToDisk(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != p.PolicyYAML {
		t.Fatal("policy mismatch")
	}
	man := filepath.Join(filepath.Dir(path), "manifest.json")
	if _, err := os.Stat(man); err != nil {
		t.Fatal(err)
	}
}
