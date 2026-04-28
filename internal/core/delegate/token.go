package delegate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	tokenPrefix = "del_"
	keyDomain   = "faramesh.delegate.v1"
)

// DeriveKey produces a delegation-signing key from a parent key (typically
// the daemon's DPR HMAC key) using a fixed domain separator. This avoids
// reusing the parent key directly while not requiring a second persisted
// secret.
func DeriveKey(parent []byte) []byte {
	mac := hmac.New(sha256.New, parent)
	mac.Write([]byte(keyDomain))
	return mac.Sum(nil)
}

// tokenPayload is the canonical signed body inside a token. Field order is
// significant: encoding/json marshals struct fields in declaration order, so
// the wire form is stable across processes.
type tokenPayload struct {
	From      string `json:"f"`
	To        string `json:"t"`
	Scope     string `json:"s"`
	Ceiling   string `json:"c,omitempty"`
	IssuedAt  int64  `json:"i"`
	ExpiresAt int64  `json:"e"`
	Depth     int    `json:"d"`
}

// Issue produces an opaque token of the form "del_<b64payload>.<b64hmac>".
// The payload is canonical JSON; the MAC is over the payload bytes.
func Issue(g Grant, key []byte) (string, error) {
	pl := tokenPayload{
		From:      g.FromAgent,
		To:        g.ToAgent,
		Scope:     g.Scope,
		Ceiling:   g.Ceiling,
		IssuedAt:  g.IssuedAt.UTC().Unix(),
		ExpiresAt: g.ExpiresAt.UTC().Unix(),
		Depth:     g.ChainDepth,
	}
	body, err := json.Marshal(pl)
	if err != nil {
		return "", fmt.Errorf("delegate: marshal token payload: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	sig := mac.Sum(nil)
	enc := base64.RawURLEncoding
	return tokenPrefix + enc.EncodeToString(body) + "." + enc.EncodeToString(sig), nil
}

// ErrInvalidToken is returned when a token is malformed or its MAC fails.
var ErrInvalidToken = errors.New("delegate: invalid token")

// Parse decodes a token, verifies its MAC, and returns the embedded grant
// fields. It does NOT consult the store; callers that care about revocation
// or expiry must check separately.
func Parse(token string, key []byte) (Grant, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return Grant{}, fmt.Errorf("%w: missing prefix", ErrInvalidToken)
	}
	rest := strings.TrimPrefix(token, tokenPrefix)
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return Grant{}, fmt.Errorf("%w: malformed token", ErrInvalidToken)
	}
	enc := base64.RawURLEncoding
	body, err := enc.DecodeString(parts[0])
	if err != nil {
		return Grant{}, fmt.Errorf("%w: payload decode: %v", ErrInvalidToken, err)
	}
	gotSig, err := enc.DecodeString(parts[1])
	if err != nil {
		return Grant{}, fmt.Errorf("%w: signature decode: %v", ErrInvalidToken, err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	wantSig := mac.Sum(nil)
	if !hmac.Equal(gotSig, wantSig) {
		return Grant{}, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	var pl tokenPayload
	if err := json.Unmarshal(body, &pl); err != nil {
		return Grant{}, fmt.Errorf("%w: payload unmarshal: %v", ErrInvalidToken, err)
	}
	return Grant{
		Token:      token,
		FromAgent:  pl.From,
		ToAgent:    pl.To,
		Scope:      pl.Scope,
		Ceiling:    pl.Ceiling,
		IssuedAt:   time.Unix(pl.IssuedAt, 0).UTC(),
		ExpiresAt:  time.Unix(pl.ExpiresAt, 0).UTC(),
		ChainDepth: pl.Depth,
	}, nil
}
