package dpr

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "os"
    "path/filepath"
)

// LocalKMSSigner is a lightweight local KMS adapter for testing and on-prem
// deployments. It expects keys under <dataDir>/kms/<keyID> with files:
// - priv (base64-encoded ed25519 private key)
// - pub  (base64-encoded ed25519 public key)
type LocalKMSSigner struct {
    keyDir string
    keyID  string
    priv   ed25519.PrivateKey
    pub    ed25519.PublicKey
}

func NewLocalKMSSigner(dataDir, keyID string) (*LocalKMSSigner, error) {
    kd := filepath.Join(dataDir, "kms", keyID)
    privPath := filepath.Join(kd, "priv")
    pubPath := filepath.Join(kd, "pub")
    privRaw, err := os.ReadFile(privPath)
    if err != nil {
        return nil, fmt.Errorf("read local kms priv: %w", err)
    }
    privBytes, err := base64.StdEncoding.DecodeString(string(privRaw))
    if err != nil {
        return nil, fmt.Errorf("decode local kms priv: %w", err)
    }
    if len(privBytes) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("invalid local kms priv size: %d", len(privBytes))
    }
    pubRaw, err := os.ReadFile(pubPath)
    if err != nil {
        return nil, fmt.Errorf("read local kms pub: %w", err)
    }
    pubBytes, err := base64.StdEncoding.DecodeString(string(pubRaw))
    if err != nil {
        return nil, fmt.Errorf("decode local kms pub: %w", err)
    }
    if len(pubBytes) != ed25519.PublicKeySize {
        return nil, fmt.Errorf("invalid local kms pub size: %d", len(pubBytes))
    }
    return &LocalKMSSigner{keyDir: kd, keyID: keyID, priv: ed25519.PrivateKey(privBytes), pub: ed25519.PublicKey(pubBytes)}, nil
}

func (l *LocalKMSSigner) ID() string {
    sum := sha256.Sum256(l.pub)
    return hex.EncodeToString(sum[:])
}

func (l *LocalKMSSigner) PublicKey() ([]byte, error) { return l.pub, nil }

func (l *LocalKMSSigner) Sign(data []byte) ([]byte, error) {
    if len(l.priv) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("invalid local kms private key size")
    }
    sig := ed25519.Sign(l.priv, data)
    return sig, nil
}
