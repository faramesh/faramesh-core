package fpl

import (
	"fmt"
	"strings"
	"unicode"
)

type Effect string

const (
	EffectPermit Effect = "permit"
	EffectDeny   Effect = "deny"
	EffectDefer  Effect = "defer"
)

const strictDenyReasonCodePrefix = "FPL_STRICT_DENY"

type NotifyMetadata struct {
	Target string `json:"target"`
}

// CompiledRule is policy-ready IR emitted from parsed FPL rules.
type CompiledRule struct {
	Effect      Effect          `json:"effect"`
	Tool        string          `json:"tool"`
	When        string          `json:"when,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	ReasonCode  string          `json:"reason_code,omitempty"`
	Notify      *NotifyMetadata `json:"notify,omitempty"`
	StrictDeny  bool            `json:"strict_deny,omitempty"`
	SourceValue string          `json:"source_effect,omitempty"`
}

var effectAliases = map[string]Effect{
	"permit":  EffectPermit,
	"allow":   EffectPermit,
	"approve": EffectPermit,
	"deny":    EffectDeny,
	"block":   EffectDeny,
	"reject":  EffectDeny,
	"defer":   EffectDefer,
}

func CompileRules(rules []*Rule) ([]*CompiledRule, error) {
	out := make([]*CompiledRule, 0, len(rules))
	for i, r := range rules {
		compiled, err := CompileRule(r)
		if err != nil {
			return nil, fmt.Errorf("compile rule %d: %w", i+1, err)
		}
		out = append(out, compiled)
	}
	return out, nil
}

func CompileRule(rule *Rule) (*CompiledRule, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}
	if strings.TrimSpace(rule.Tool) == "" {
		return nil, fmt.Errorf("tool is required")
	}

	effect, strict, err := normalizeEffect(rule.Effect)
	if err != nil {
		return nil, err
	}

	reason := strings.TrimSpace(rule.Reason)
	compiled := &CompiledRule{
		Effect:      effect,
		Tool:        strings.TrimSpace(rule.Tool),
		When:        strings.TrimSpace(rule.Condition),
		Reason:      reason,
		StrictDeny:  strict,
		SourceValue: rule.Effect,
	}

	if notify := strings.TrimSpace(rule.Notify); notify != "" {
		compiled.Notify = &NotifyMetadata{Target: notify}
	}

	if strict {
		if compiled.Reason == "" {
			compiled.Reason = "strict deny"
		}
		compiled.ReasonCode = strictDenyReasonCode(compiled.Reason)
	} else if compiled.Reason != "" {
		compiled.ReasonCode = genericReasonCode(compiled.Reason)
	}

	return compiled, nil
}

func ParseAndCompileRules(src string) ([]*CompiledRule, error) {
	parsed, err := ParseRules(src)
	if err != nil {
		return nil, err
	}
	return CompileRules(parsed)
}


func normalizeEffect(raw string) (Effect, bool, error) {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "deny!" {
		return EffectDeny, true, nil
	}
	e, ok := effectAliases[v]
	if !ok {
		return "", false, fmt.Errorf("invalid effect %q", raw)
	}
	return e, false, nil
}

func strictDenyReasonCode(reason string) string {
	suffix := normalizedCodeToken(reason)
	if suffix == "" {
		return strictDenyReasonCodePrefix
	}
	return strictDenyReasonCodePrefix + "_" + suffix
}

func genericReasonCode(reason string) string {
	suffix := normalizedCodeToken(reason)
	if suffix == "" {
		return "FPL_REASON"
	}
	return "FPL_REASON_" + suffix
}

func normalizedCodeToken(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToUpper(r))
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}

	out := strings.Trim(b.String(), "_")
	return out
}
