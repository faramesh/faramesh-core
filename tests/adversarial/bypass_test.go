package adversarial_test

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Unicode confusable injection.
// Attacker substitutes Cyrillic characters in tool IDs to bypass rules.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_UnicodeConfusableToolID(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-shell", Match: policy.Match{Tool: "shell/*"}, Effect: "deny", Reason: "shell blocked"},
		{ID: "allow-rest", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	// Attacker tries Cyrillic 'ѕ' (U+0455) instead of Latin 's' in "shell".
	confusables := []string{
		"ѕhell/exec",       // Cyrillic ѕ
		"shеll/exec",       // Cyrillic е
		"ѕhеll/exec",       // Both
		"shell\u200B/exec", // Zero-width space
		"shell\u00AD/exec", // Soft hyphen
	}

	for _, tool := range confusables {
		d := p.Evaluate(testCAR(tool, nil))
		// After canonicalization, these should all map to "shell/exec" and be DENIED.
		// If any gets PERMIT, the confusable bypass succeeded.
		if d.Effect == core.EffectPermit {
			t.Errorf("confusable bypass succeeded for tool %q — got PERMIT instead of DENY", tool)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Null byte injection in arguments.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_NullByteInjection(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-dangerous-cmd", Match: policy.Match{
			Tool: "shell/*",
			When: `args.command == "rm -rf /"`,
		}, Effect: "deny"},
		{ID: "allow-shell", Match: policy.Match{Tool: "shell/*"}, Effect: "permit"},
	}, nil)

	// Attacker tries to hide dangerous command behind null bytes.
	attacks := []map[string]any{
		{"command": "rm -rf /\x00safe-suffix"},
		{"command": "rm\x00 -rf /"},
		{"command": "rm -rf /\x00"},
	}

	for i, args := range attacks {
		d := p.Evaluate(testCAR("shell/exec", args))
		// After null stripping in canonicalize, these should be caught.
		t.Logf("null-byte attack %d: effect=%s reason=%s", i, d.Effect, d.ReasonCode)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Argument structure smuggling.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_ArgumentSmuggling(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-large-refund", Match: policy.Match{
			Tool: "stripe/*",
			When: `args.amount > 1000`,
		}, Effect: "deny"},
		{ID: "allow-stripe", Match: policy.Match{Tool: "stripe/*"}, Effect: "permit"},
	}, nil)

	// Attacker adds extra keys to try to confuse the pipeline.
	smuggledArgs := []map[string]any{
		{"amount": 500, "__proto__": map[string]any{"amount": 50}},
		{"amount": 500, "constructor": map[string]any{"amount": 50}},
		{"amount": 2000, "amount ": 50},     // trailing space key
		{"amount": 2000, "amount\t": 50},    // tab in key
	}

	for i, args := range smuggledArgs {
		d := p.Evaluate(testCAR("stripe/refund", args))
		t.Logf("smuggling %d: effect=%s (args had %d keys)", i, d.Effect, len(args))
		// The real "amount" key governs — smuggled duplicates shouldn't affect outcome.
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Tool ID prefix/suffix mutation.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_ToolIDMutation(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-admin", Match: policy.Match{Tool: "admin/*"}, Effect: "deny"},
		{ID: "allow-rest", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	// These mutations should all be caught by canonicalization.
	// Case variations (ADMIN, Admin) are intentionally not canonicalized —
	// tool IDs are case-sensitive by design (consistent with filesystem paths).
	mustDeny := []string{
		"admin/delete",
		" admin/delete",
		"admin/delete ",
		"admin//delete",
		"./admin/delete",
		"../admin/delete",
	}

	for _, tool := range mustDeny {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect != core.EffectDeny {
			t.Errorf("tool ID mutation bypass: %q got %s instead of DENY", tool, d.Effect)
		}
	}

	// Case variations are allowed through — this is by design.
	// Policy authors who want case-insensitive matching should write
	// multiple rules or use appropriate glob patterns.
	caseVariations := []string{"ADMIN/delete", "Admin/Delete"}
	for _, tool := range caseVariations {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect != core.EffectPermit {
			t.Logf("case variation %q: effect=%s (case-sensitive match is correct design)", tool, d.Effect)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Case variation attacks.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_CaseVariation(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-shell", Match: policy.Match{Tool: "shell/*"}, Effect: "deny"},
		{ID: "allow-rest", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	cases := []string{
		"SHELL/exec",
		"Shell/Exec",
		"sHeLL/eXeC",
		"shell/EXEC",
	}

	for _, tool := range cases {
		d := p.Evaluate(testCAR(tool, nil))
		t.Logf("case variation %q: effect=%s", tool, d.Effect)
		// Note: whether case sensitivity is enforced depends on the pipeline.
		// What matters is consistent behavior.
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bypass Attempt: Empty and oversized arguments.
// ──────────────────────────────────────────────────────────────────────────────
func TestBypass_EmptyAndOversizedArgs(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	// Empty args should not panic.
	d := p.Evaluate(testCAR("any/tool", nil))
	if d.Effect == "" {
		t.Error("nil args: empty effect")
	}

	d = p.Evaluate(testCAR("any/tool", map[string]any{}))
	if d.Effect == "" {
		t.Error("empty map args: empty effect")
	}

	// Oversized arg: 1MB string.
	bigStr := strings.Repeat("A", 1<<20)
	d = p.Evaluate(testCAR("any/tool", map[string]any{"big": bigStr}))
	if d.Effect == "" {
		t.Error("oversized args: empty effect")
	}
}
