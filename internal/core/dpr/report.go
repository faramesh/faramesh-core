package dpr

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "crypto/ed25519"
)

type ResignReportRecord struct {
    RecordID     string `json:"record_id"`
    OldHash      string `json:"old_hash"`
    NewHash      string `json:"new_hash"`
    ReSigned     bool   `json:"re_signed"`
    Note         string `json:"note,omitempty"`
    OldSignerID  string `json:"old_signer_id,omitempty"`
    NewSignerID  string `json:"new_signer_id,omitempty"`
}

type OperatorSignature struct {
    SignatureB64     string `json:"signature_b64"`
    SignerPublicB64  string `json:"signer_public_key_b64"`
    SignatureAlg     string `json:"signature_alg"`
}

type ResignReport struct {
    ReportID   string                `json:"report_id"`
    CreatedAt  string                `json:"created_at"`
    CreatedBy  string                `json:"created_by,omitempty"`
    Records    []ResignReportRecord  `json:"records"`
    Summary    map[string]int        `json:"summary"`
    OperatorSignature OperatorSignature `json:"operator_signature"`
}

// ComputeSignerIDFromPubB64 returns hex(sha256(pub)) given base64-encoded public key.
func ComputeSignerIDFromPubB64(pubB64 string) (string, error) {
    if pubB64 == "" {
        return "", nil
    }
    pub, err := base64.StdEncoding.DecodeString(pubB64)
    if err != nil {
        return "", err
    }
    sum := sha256.Sum256(pub)
    return hex.EncodeToString(sum[:]), nil
}

// ComputeSignerIDFromPubB64 returns hex(sha256(pub)) given base64-encoded public key.
func (r *ResignReport) ComputeSignerIDFromPubB64AsMethod(pubB64 string) (string, error) {
    if pubB64 == "" {
        return "", nil
    }
    pub, err := base64.StdEncoding.DecodeString(pubB64)
    if err != nil {
        return "", err
    }
    sum := sha256.Sum256(pub)
    return hex.EncodeToString(sum[:]), nil
}

// MarshalWithoutSignature marshals the report with an empty OperatorSignature.
func (r *ResignReport) MarshalWithoutSignature() ([]byte, error) {
    tmp := *r
    tmp.OperatorSignature = OperatorSignature{}
    return json.MarshalIndent(&tmp, "", "  ")
}

// AttachOperatorSignature sets the OperatorSignature given a signature and signer pub (both raw bytes).
func (r *ResignReport) AttachOperatorSignature(sig []byte, signerPub []byte) {
    r.OperatorSignature = OperatorSignature{
        SignatureB64:    base64.StdEncoding.EncodeToString(sig),
        SignerPublicB64: base64.StdEncoding.EncodeToString(signerPub),
        SignatureAlg:    "ed25519",
    }
}

// VerifyOperatorSignature verifies the embedded operator signature and returns error if invalid.
func (r *ResignReport) VerifyOperatorSignature() error {
    sigB64 := r.OperatorSignature.SignatureB64
    signerB64 := r.OperatorSignature.SignerPublicB64
    if sigB64 == "" || signerB64 == "" {
        return fmt.Errorf("missing operator signature fields")
    }
    sig, err := base64.StdEncoding.DecodeString(sigB64)
    if err != nil {
        return fmt.Errorf("decode signature: %w", err)
    }
    signerPub, err := base64.StdEncoding.DecodeString(signerB64)
    if err != nil {
        return fmt.Errorf("decode signer pub: %w", err)
    }
    payload, err := r.MarshalWithoutSignature()
    if err != nil {
        return fmt.Errorf("marshal payload: %w", err)
    }
    if len(signerPub) != ed25519.PublicKeySize {
        return fmt.Errorf("invalid operator public key size: %d", len(signerPub))
    }
    if !ed25519.Verify(ed25519.PublicKey(signerPub), payload, sig) {
        return fmt.Errorf("operator signature verification failed")
    }
    return nil
}
