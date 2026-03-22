package artifactverify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// SignFile signs the entire file contents with an Ed25519 private key (PEM).
func SignFile(privPEM []byte, filePath string) ([]byte, error) {
	priv, err := parseEd25519PrivateKeyPEM(privPEM)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data), nil
}

// VerifyFileSignature checks Ed25519 signature over file contents.
func VerifyFileSignature(pubPEM []byte, filePath string, signature []byte) error {
	pub, err := parseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, signature) {
		return fmt.Errorf("ed25519 verification failed")
	}
	return nil
}

func parseEd25519PrivateKeyPEM(pemStr []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemStr)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	if strings.Contains(block.Type, "PRIVATE KEY") {
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
		return priv, nil
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}

func parseEd25519PublicKeyPEM(pemStr []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemStr)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public key")
	}
	if strings.Contains(block.Type, "PUBLIC KEY") {
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not Ed25519")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}

// DecodeSignatureArg accepts raw bytes or standard base64 (and strips whitespace).
func DecodeSignatureArg(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty signature")
	}
	// try base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, fmt.Errorf("signature must be %d-byte Ed25519 value (base64-encoded)", ed25519.SignatureSize)
}
