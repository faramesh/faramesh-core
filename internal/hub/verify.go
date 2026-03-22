package hub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// Sum256Hex returns lowercase hex SHA-256 of b.
func Sum256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// VerifyPolicySignature checks Ed25519 signature over raw policy bytes using PEM public key from sig.
func VerifyPolicySignature(policy []byte, sig *PackSignature) error {
	if sig == nil {
		return fmt.Errorf("missing signature")
	}
	if strings.ToLower(strings.TrimSpace(sig.Algorithm)) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q (need ed25519)", sig.Algorithm)
	}
	if sig.PublicKeyPEM == "" {
		return fmt.Errorf("missing signature.public_key_pem")
	}
	rawSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.ValueB64))
	if err != nil {
		return fmt.Errorf("decode value_b64: %w", err)
	}
	pub, err := parseEd25519PublicKeyPEM(sig.PublicKeyPEM)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, policy, rawSig) {
		return fmt.Errorf("ed25519 verification failed")
	}
	return nil
}

func parseEd25519PublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public_key_pem")
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
