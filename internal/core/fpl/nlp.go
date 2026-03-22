package fpl

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// NLPToFPL compiles a natural language policy description into FPL source.
// It performs pattern matching on common policy phrases to produce valid FPL.
// For more complex NLP, a hosted LLM endpoint can be used (future extension).
func NLPToFPL(agentID, nlp string) string {
	sentences := splitSentences(nlp)
	var rules []*Rule
	for _, s := range sentences {
		r := nlpSentenceToRule(s)
		if r != nil {
			rules = append(rules, r)
		}
	}

	decompRules := make([]DecompileRule, 0, len(rules))
	for _, r := range rules {
		dr := DecompileRule{
			Effect:     r.Effect,
			Tool:       r.Tool,
			When:       r.Condition,
			Notify:     r.Notify,
			Reason:     r.Reason,
			StrictDeny: r.Effect == "deny!",
		}
		if dr.StrictDeny {
			dr.Effect = "deny"
		}
		decompRules = append(decompRules, dr)
	}

	if agentID == "" {
		agentID = "my-agent"
	}
	return DecompileToFPL(agentID, "deny", nil, nil, decompRules, nil)
}

var (
	denyPattern   = regexp.MustCompile(`(?i)\b(deny|block|reject|never allow|prohibit|forbid)\b`)
	deferPattern  = regexp.MustCompile(`(?i)\b(defer|require approval|needs approval|human review|escalate)\b`)
	permitPattern = regexp.MustCompile(`(?i)\b(permit|allow|approve|enable)\b`)

	shellPattern  = regexp.MustCompile(`(?i)\b(shell|bash|terminal|subprocess|exec)\b`)
	refundPattern = regexp.MustCompile(`(?i)\b(refund|chargeback|reversal)\b`)
	amountPattern = regexp.MustCompile(`(?i)\$\s*(\d+(?:\.\d+)?)`)
	overPattern   = regexp.MustCompile(`(?i)\bover\s+\$?\s*(\d+(?:\.\d+)?)`)
	underPattern  = regexp.MustCompile(`(?i)\bunder\s+\$?\s*(\d+(?:\.\d+)?)`)
	toolPattern   = regexp.MustCompile(`(?i)\btool[s]?\s+(?:called\s+)?["']?([a-zA-Z0-9_/.*-]+)["']?`)
	notifyPattern = regexp.MustCompile(`(?i)\b(?:notify|alert|tell|inform)\s+["']?([a-zA-Z0-9_@.-]+)["']?`)
)

func nlpSentenceToRule(sentence string) *Rule {
	s := strings.TrimSpace(sentence)
	if s == "" {
		return nil
	}

	rule := &Rule{}

	// Determine effect.
	switch {
	case denyPattern.MatchString(s):
		if strings.Contains(strings.ToLower(s), "never") || strings.Contains(strings.ToLower(s), "always deny") {
			rule.Effect = "deny!"
		} else {
			rule.Effect = "deny"
		}
	case deferPattern.MatchString(s):
		rule.Effect = "defer"
	case permitPattern.MatchString(s):
		rule.Effect = "permit"
	default:
		rule.Effect = "deny"
	}

	// Determine tool.
	if shellPattern.MatchString(s) {
		rule.Tool = "shell/*"
	} else if refundPattern.MatchString(s) {
		rule.Tool = "stripe/refund"
	} else if m := toolPattern.FindStringSubmatch(s); len(m) > 1 {
		rule.Tool = m[1]
	} else {
		rule.Tool = "*"
	}

	// Determine condition.
	if m := overPattern.FindStringSubmatch(s); len(m) > 1 {
		amt, _ := strconv.ParseFloat(m[1], 64)
		rule.Condition = fmt.Sprintf("amount > %.0f", amt)
	} else if m := underPattern.FindStringSubmatch(s); len(m) > 1 {
		amt, _ := strconv.ParseFloat(m[1], 64)
		rule.Condition = fmt.Sprintf("amount < %.0f", amt)
	} else if m := amountPattern.FindStringSubmatch(s); len(m) > 1 {
		amt, _ := strconv.ParseFloat(m[1], 64)
		if strings.Contains(strings.ToLower(s), "above") || strings.Contains(strings.ToLower(s), "more than") || strings.Contains(strings.ToLower(s), "exceed") {
			rule.Condition = fmt.Sprintf("amount > %.0f", amt)
		} else if strings.Contains(strings.ToLower(s), "below") || strings.Contains(strings.ToLower(s), "less than") {
			rule.Condition = fmt.Sprintf("amount < %.0f", amt)
		}
	}

	// Determine notify.
	if m := notifyPattern.FindStringSubmatch(s); len(m) > 1 {
		rule.Notify = m[1]
	}

	// Reason is the original sentence, cleaned.
	rule.Reason = cleanReason(s)

	return rule
}

func splitSentences(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		for _, sent := range strings.Split(p, ";") {
			trimmed := strings.TrimSpace(sent)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	if len(out) == 0 {
		return []string{strings.TrimSpace(s)}
	}
	return out
}

func cleanReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
