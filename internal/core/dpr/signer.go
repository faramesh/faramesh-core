package dpr

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
)

// Signer abstracts a signing backend for DPR records.
type Signer interface {
    // ID returns a stable key identifier (hex-encoded sha256(pub) or KMS key ARN)
    ID() string
    // PublicKey returns the raw public key bytes
    PublicKey() ([]byte, error)
    // Sign signs the input bytes and returns a signature blob
    Sign(data []byte) ([]byte, error)
}

// FileSigner is a simple in-process signer that wraps an Ed25519 private key.
// It expects the caller to provide the raw private and public key bytes.
type FileSigner struct {
    priv []byte
    pub  []byte
}

func NewFileSigner(priv, pub []byte) *FileSigner {
    return &FileSigner{priv: priv, pub: pub}
}

func (f *FileSigner) ID() string {
    h := sha256.Sum256(f.pub)
    return hex.EncodeToString(h[:])
}

func (f *FileSigner) PublicKey() ([]byte, error) { return f.pub, nil }

func (f *FileSigner) Sign(data []byte) ([]byte, error) {
    if len(f.priv) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(f.priv))
    }
    sig := ed25519.Sign(ed25519.PrivateKey(f.priv), data)
    return sig, nil
}
