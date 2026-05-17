package registry

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Ed25519PublicKeyPEM encodes a raw Ed25519 public key as PKIX PEM.
func Ed25519PublicKeyPEM(publicKeyB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key length %d", len(raw))
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ensureRegistryPublicKey(stackDir string, publicKeyB64 string) error {
	if strings.TrimSpace(stackDir) == "" || strings.TrimSpace(publicKeyB64) == "" {
		return nil
	}
	pemBytes, err := Ed25519PublicKeyPEM(publicKeyB64)
	if err != nil {
		return err
	}
	dir := filepath.Join(stackDir, ".faramesh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "registry.pub")
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return nil
	}
	return os.WriteFile(path, pemBytes, 0o644)
}
