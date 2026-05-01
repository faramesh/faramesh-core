package dpr

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// SignWithEd25519 signs the record's canonical bytes with the provided
// Ed25519 private key and records the signature and signer public key
// (base64-encoded) on the Record. This function intentionally uses the
// existing CanonicalBytes() implementation for now; a future step will
// migrate canonicalization to JCS (RFC 8785) and re-sign as part of that
// migration path.
func (r *Record) SignWithEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	if len(priv) == 0 {
		return errors.New("ed25519 private key is empty")
	}
	// Use existing canonical bytes for initial rollout.
	msg := r.CanonicalBytes()
	sig := ed25519.Sign(priv, msg)
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	r.SignatureAlg = "ed25519"
	r.SignerPublicKey = base64.StdEncoding.EncodeToString(pub)
	return nil
}

// VerifyEd25519 verifies the record's Ed25519 signature using the stored
// signer public key. Returns true if the signature verifies.
func (r *Record) VerifyEd25519() (bool, error) {
	if r.SignatureAlg != "ed25519" {
		return false, errors.New("record not signed with ed25519")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(r.SignerPublicKey)
	if err != nil {
		return false, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return false, err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 public key size")
	}
	ok := ed25519.Verify(ed25519.PublicKey(pubBytes), r.CanonicalBytes(), sigBytes)
	return ok, nil
}
