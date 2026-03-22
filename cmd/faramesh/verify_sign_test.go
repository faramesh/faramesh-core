package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyManifestCLI(t *testing.T) {
	root := findRepoRoot(t)
	dir := t.TempDir()
	payload := []byte("manifest-test-payload")
	f := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(f, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".", "verify", "digest", f)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	digest := strings.TrimSpace(string(out))

	m := map[string]any{
		"version": 1,
		"artifacts": []map[string]string{
			{"path": "blob.txt", "sha256": digest},
		},
	}
	raw, _ := json.Marshal(m)
	mf := filepath.Join(dir, "m.json")
	if err := os.WriteFile(mf, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd2 := exec.Command("go", "run", ".", "verify", "manifest", mf, "--base-dir", dir)
	cmd2.Dir = filepath.Join(root, "cmd", "faramesh")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "✓") {
		t.Fatalf("unexpected: %s", out2)
	}
}

func TestSignVerifyRoundTripCLI(t *testing.T) {
	root := findRepoRoot(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(data, []byte("sign-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	privPath := filepath.Join(dir, "priv.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "sig.b64")

	cmd := exec.Command("go", "run", ".", "sign", "file", "--private-key", privPath, "--file", data, "--output", sigPath)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	cmd2 := exec.Command("go", "run", ".", "verify", "signature", "--public-key", pubPath, "--file", data, "--signature", sigPath)
	cmd2.Dir = filepath.Join(root, "cmd", "faramesh")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "✓") {
		t.Fatalf("unexpected: %s", out2)
	}
}
