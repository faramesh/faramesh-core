package dpr

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	// Register built-in providers: "file" and "localkms"
	_ = RegisterKMSProvider("file", newFileSignerFromURI)
	_ = RegisterKMSProvider("localkms", newLocalKMSSignerFromURI)
}

// newFileSignerFromURI constructs a FileSigner from file://... or just "file" shorthand.
// The URI should point to base64-encoded private+public key pair or use data-dir defaults.
func newFileSignerFromURI(uri, dataDir string) (Signer, error) {
	// Shorthand: if uri is just "file" or "file://", use on-disk keys from dataDir
	if uri == "file" || uri == "file://" {
		privPath := filepath.Join(dataDir, "faramesh.ed25519.key")
		pubPath := filepath.Join(dataDir, "faramesh.ed25519.pub")
		priv, err := os.ReadFile(privPath)
		if err != nil {
			return nil, fmt.Errorf("read file signer private key: %w", err)
		}
		pub, err := os.ReadFile(pubPath)
		if err != nil {
			return nil, fmt.Errorf("read file signer public key: %w", err)
		}
		privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(priv)))
		if err != nil {
			return nil, fmt.Errorf("decode file signer private key: %w", err)
		}
		pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pub)))
		if err != nil {
			return nil, fmt.Errorf("decode file signer public key: %w", err)
		}
		return NewFileSigner(privBytes, pubBytes), nil
	}
	return nil, fmt.Errorf("file:// URI format not fully supported; use shorthand 'file' for default data-dir keys")
}

// newLocalKMSSignerFromURI constructs a LocalKMSSigner from localkms://keyid
func newLocalKMSSignerFromURI(uri, dataDir string) (Signer, error) {
	const prefix = "localkms://"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("invalid localkms uri: %s", uri)
	}
	keyID := strings.TrimPrefix(uri, prefix)
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("localkms uri missing key id")
	}
	return NewLocalKMSSigner(dataDir, keyID)
}
