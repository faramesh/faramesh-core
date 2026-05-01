package delegate

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleGrant() Grant {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	return Grant{
		FromAgent:  "supervisor",
		ToAgent:    "worker",
		Scope:      "stripe/*",
		Ceiling:    "amount<=500",
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
		ChainDepth: 2,
		Active:     true,
	}
}

func TestDeriveKey_DomainSeparation(t *testing.T) {
	parent := []byte("dpr-parent-key")
	got := DeriveKey(parent)
	if len(got) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d", len(got))
	}
	// Same parent yields identical derived key (deterministic).
	if string(DeriveKey(parent)) != string(got) {
		t.Error("DeriveKey is not deterministic")
	}
	// Different parent yields different key.
	if string(DeriveKey([]byte("other"))) == string(got) {
		t.Error("expected different keys for different parents")
	}
}

func TestIssue_AndParse_Roundtrip(t *testing.T) {
	key := DeriveKey([]byte("k"))
	g := sampleGrant()
	tok, err := Issue(g, key)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(tok, "del_") {
		t.Errorf("expected del_ prefix, got %s", tok)
	}
	parsed, err := Parse(tok, key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.FromAgent != g.FromAgent || parsed.ToAgent != g.ToAgent {
		t.Errorf("roundtrip from/to mismatch: %+v", parsed)
	}
	if parsed.Scope != g.Scope || parsed.Ceiling != g.Ceiling {
		t.Errorf("roundtrip scope/ceiling mismatch: %+v", parsed)
	}
	if !parsed.IssuedAt.Equal(g.IssuedAt) || !parsed.ExpiresAt.Equal(g.ExpiresAt) {
		t.Errorf("roundtrip time mismatch: %+v", parsed)
	}
	if parsed.ChainDepth != g.ChainDepth {
		t.Errorf("roundtrip depth mismatch: %d", parsed.ChainDepth)
	}
}

func TestParse_RejectsTamper(t *testing.T) {
	key := DeriveKey([]byte("k"))
	tok, err := Issue(sampleGrant(), key)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Flip the last char of payload.
	parts := strings.Split(strings.TrimPrefix(tok, "del_"), ".")
	if len(parts) != 2 {
		t.Fatalf("token shape unexpected")
	}
	tampered := "del_" + parts[0][:len(parts[0])-1] + "X." + parts[1]
	if _, err := Parse(tampered, key); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on payload tamper, got %v", err)
	}

	// Wrong key.
	if _, err := Parse(tok, DeriveKey([]byte("other"))); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on wrong key, got %v", err)
	}
}

func TestParse_RejectsMalformed(t *testing.T) {
	key := DeriveKey([]byte("k"))
	cases := []string{
		"",
		"not-a-token",
		"del_only-one-segment",
		"del_!!!.???",
	}
	for _, c := range cases {
		if _, err := Parse(c, key); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expected ErrInvalidToken for %q, got %v", c, err)
		}
	}
}
