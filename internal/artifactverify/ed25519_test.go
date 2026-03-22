package artifactverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir := t.TempDir()
	f := filepath.Join(dir, "blob.bin")
	payload := []byte("artifact-bytes")
	if err := os.WriteFile(f, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sig, err := SignFile(privPEM, f)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFileSignature(pubPEM, f, sig); err != nil {
		t.Fatal(err)
	}
}
