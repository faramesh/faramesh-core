package artifactverify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyManifest_ok(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := FileSHA256Hex(p)
	if err != nil {
		t.Fatal(err)
	}
	m := &ManifestV1{Version: 1, Artifacts: []ArtifactDigest{{Path: "a.txt", SHA256: h}}}
	if err := VerifyManifest(dir, m); err != nil {
		t.Fatal(err)
	}
}

func TestBuildManifestV1(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "sub", "b.txt")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := BuildManifestV1(dir, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Artifacts) != 2 {
		t.Fatalf("len %d", len(m.Artifacts))
	}
	if err := VerifyManifest(dir, m); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyManifest_mismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &ManifestV1{Version: 1, Artifacts: []ArtifactDigest{{Path: "a.txt", SHA256: "00"}}}
	if err := VerifyManifest(dir, m); err == nil {
		t.Fatal("expected error")
	}
}
