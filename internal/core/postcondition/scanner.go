// Package postcondition implements post-execution output scanning.
// After a tool call is PERMIT'd and executed, its output passes through
// these scanners before reaching the agent's context. This prevents
// secrets, PII, and prompt injection patterns from leaking into the
// agent's reasoning space.
//
// This implements Layer 2.2 from the Faramesh architecture spec:
// "Post-Execution Output Interception".
package postcondition

import (
	"fmt"
	"regexp"
	"strings"
)

// Action defines what happens when a scanner pattern matches.
type Action string

const (
	ActionRedact   Action = "redact"   // replace matched text with placeholder
	ActionHash     Action = "hash"     // replace with deterministic hash
	ActionDeny     Action = "deny"     // block entire output
	ActionWarn     Action = "warn"     // pass through but log warning
	ActionTruncate Action = "truncate" // truncate output at N bytes
)

// Category is a named set of built-in scanner patterns.
type Category string

const (
	CatSecretsAll     Category = "secrets_all"
	CatSecretAWSKey   Category = "secret_aws_key"
	CatSecretGitHub   Category = "secret_github_pat"
	CatSecretGCPSA    Category = "secret_gcp_sa"
	CatSecretAzure    Category = "secret_azure_conn"
	CatSecretDBURI    Category = "secret_database_uri"
	CatSecretSSHKey   Category = "secret_ssh_key"
	CatSecretOpenAI   Category = "secret_openai_key"
	CatSecretAnthropic Category = "secret_anthropic_key"
	CatSecretBearer   Category = "secret_bearer_token"

	CatPIIEmail      Category = "pii_email"
	CatPIIPhone      Category = "pii_phone"
	CatPIISSN        Category = "pii_ssn"
	CatPIICreditCard Category = "pii_credit_card"
	CatPIIIPAddress  Category = "pii_ip_address"
	CatPIINPI        Category = "pii_npi"
	CatPIIIBAN       Category = "pii_iban"

	CatInjection Category = "prompt_injection"
)

// ScanRule is a single post-condition scanning rule from the policy.
type ScanRule struct {
	Pattern     string   `yaml:"pattern"`      // regex pattern (mutually exclusive with Category)
	Category    Category `yaml:"category"`      // named pattern category
	Action      Action   `yaml:"action"`        // what to do on match
	Replacement string   `yaml:"replacement"`   // custom replacement text (for redact)
	Reason      string   `yaml:"reason"`        // human-readable reason for deny/warn
}

// PostRule is a post-condition rule block from the policy.
type PostRule struct {
	ID    string     `yaml:"id"`
	Match PostMatch  `yaml:"match"`
	Scan  []ScanRule `yaml:"scan"`
}

// PostMatch specifies which tool outputs this post-rule applies to.
type PostMatch struct {
	Tool string `yaml:"tool"` // glob pattern, same as pre-condition rules
}

// ScanResult is the outcome of scanning a tool output.
type ScanResult struct {
	Outcome    Outcome       // PASS, REDACTED, or DENIED
	Output     string        // the (possibly redacted) output
	ReasonCode string        // machine-readable reason if denied
	Reason     string        // human-readable reason if denied
	Matches    []ScanMatch   // all pattern matches found
}

// Outcome is the post-condition scan result.
type Outcome string

const (
	OutcomePass     Outcome = "PASS"
	OutcomeRedacted Outcome = "REDACTED"
	OutcomeDenied   Outcome = "DENIED"
	OutcomeWarned   Outcome = "WARNED"
)

// ScanMatch records a single pattern match in the output.
type ScanMatch struct {
	Category    string `json:"category"`
	Action      Action `json:"action"`
	ReasonCode  string `json:"reason_code"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
}

// Scanner holds compiled post-condition rules and executes output scanning.
type Scanner struct {
	rules    []PostRule
	compiled map[string][]*compiledScan // tool pattern -> compiled scans
	maxBytes int                        // max output size (0 = no limit)
}

type compiledScan struct {
	re          *regexp.Regexp
	action      Action
	replacement string
	reason      string
	reasonCode  string
}

// NewScanner compiles post-condition rules.
func NewScanner(rules []PostRule, maxOutputBytes int) (*Scanner, error) {
	s := &Scanner{
		rules:    rules,
		compiled: make(map[string][]*compiledScan),
		maxBytes: maxOutputBytes,
	}
	for _, rule := range rules {
		var scans []*compiledScan
		for _, sr := range rule.Scan {
			compiled, err := compileScanRule(sr)
			if err != nil {
				return nil, fmt.Errorf("post-rule %s: %w", rule.ID, err)
			}
			scans = append(scans, compiled...)
		}
		s.compiled[rule.Match.Tool] = append(s.compiled[rule.Match.Tool], scans...)
	}
	return s, nil
}

// Scan processes a tool output through applicable post-condition rules.
func (s *Scanner) Scan(toolID, output string) ScanResult {
	if s == nil || len(s.compiled) == 0 {
		return ScanResult{Outcome: OutcomePass, Output: output}
	}

	// Enforce max output size.
	if s.maxBytes > 0 && len(output) > s.maxBytes {
		return ScanResult{
			Outcome:    OutcomeDenied,
			Output:     "",
			ReasonCode: "OUTPUT_SIZE_EXCEEDED",
			Reason:     fmt.Sprintf("output size %d exceeds limit %d bytes", len(output), s.maxBytes),
		}
	}

	// Find applicable scans for this tool.
	var applicable []*compiledScan
	for pattern, scans := range s.compiled {
		if matchToolPattern(pattern, toolID) {
			applicable = append(applicable, scans...)
		}
	}
	if len(applicable) == 0 {
		return ScanResult{Outcome: OutcomePass, Output: output}
	}

	result := ScanResult{Outcome: OutcomePass, Output: output}
	redacted := output

	for _, cs := range applicable {
		locs := cs.re.FindAllStringIndex(redacted, -1)
		if len(locs) == 0 {
			continue
		}

		for _, loc := range locs {
			result.Matches = append(result.Matches, ScanMatch{
				Category:   cs.reasonCode,
				Action:     cs.action,
				ReasonCode: cs.reasonCode,
				Offset:     loc[0],
				Length:      loc[1] - loc[0],
			})
		}

		switch cs.action {
		case ActionDeny:
			return ScanResult{
				Outcome:    OutcomeDenied,
				Output:     "",
				ReasonCode: cs.reasonCode,
				Reason:     cs.reason,
				Matches:    result.Matches,
			}
		case ActionRedact:
			replacement := "[REDACTED]"
			if cs.replacement != "" {
				replacement = cs.replacement
			}
			redacted = cs.re.ReplaceAllString(redacted, replacement)
			result.Outcome = OutcomeRedacted
		case ActionWarn:
			if result.Outcome == OutcomePass {
				result.Outcome = OutcomeWarned
			}
		}
	}

	result.Output = redacted
	return result
}

// compileScanRule expands a ScanRule into one or more compiled regex scans.
func compileScanRule(sr ScanRule) ([]*compiledScan, error) {
	if sr.Pattern != "" {
		re, err := regexp.Compile(sr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q: %w", sr.Pattern, err)
		}
		return []*compiledScan{{
			re:          re,
			action:      sr.Action,
			replacement: sr.Replacement,
			reason:      sr.Reason,
			reasonCode:  "CUSTOM_PATTERN",
		}}, nil
	}

	if sr.Category != "" {
		return categoryToScans(sr.Category, sr.Action, sr.Replacement, sr.Reason)
	}

	return nil, fmt.Errorf("scan rule must specify either pattern or category")
}

// categoryToScans expands a named category into compiled regex patterns.
func categoryToScans(cat Category, action Action, replacement, reason string) ([]*compiledScan, error) {
	defs := categoryPatterns[cat]
	if len(defs) == 0 {
		// Check if it's a meta-category.
		if cat == CatSecretsAll {
			var all []*compiledScan
			for c := range categoryPatterns {
				if strings.HasPrefix(string(c), "secret_") {
					scans, err := categoryToScans(c, action, replacement, reason)
					if err != nil {
						return nil, err
					}
					all = append(all, scans...)
				}
			}
			return all, nil
		}
		return nil, fmt.Errorf("unknown category %q", cat)
	}

	var scans []*compiledScan
	for _, def := range defs {
		re, err := regexp.Compile(def.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile category %q pattern: %w", cat, err)
		}
		rc := def.reasonCode
		r := reason
		if r == "" {
			r = def.reason
		}
		scans = append(scans, &compiledScan{
			re:          re,
			action:      action,
			replacement: replacement,
			reason:      r,
			reasonCode:  rc,
		})
	}
	return scans, nil
}

type patternDef struct {
	pattern    string
	reasonCode string
	reason     string
}

// categoryPatterns maps named categories to their regex patterns.
var categoryPatterns = map[Category][]patternDef{
	CatSecretAWSKey: {{
		pattern:    `AKIA[0-9A-Z]{16}`,
		reasonCode: "OUTPUT_SECRET_AWS_KEY",
		reason:     "AWS access key detected in output",
	}},
	CatSecretGitHub: {{
		pattern:    `ghp_[a-zA-Z0-9]{36}`,
		reasonCode: "OUTPUT_SECRET_GITHUB_PAT",
		reason:     "GitHub personal access token detected in output",
	}},
	CatSecretGCPSA: {{
		pattern:    `"type"\s*:\s*"service_account"`,
		reasonCode: "OUTPUT_SECRET_GCP_SA",
		reason:     "GCP service account credential detected in output",
	}},
	CatSecretAzure: {{
		pattern:    `(?i)(DefaultEndpointsProtocol=https?;AccountName=)`,
		reasonCode: "OUTPUT_SECRET_AZURE_CONN",
		reason:     "Azure connection string detected in output",
	}},
	CatSecretDBURI: {{
		pattern:    `(?i)(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@`,
		reasonCode: "OUTPUT_SECRET_DATABASE_URI",
		reason:     "database URI with credentials detected in output",
	}},
	CatSecretSSHKey: {{
		pattern:    `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`,
		reasonCode: "OUTPUT_SECRET_SSH_KEY",
		reason:     "SSH/TLS private key detected in output",
	}},
	CatSecretOpenAI: {{
		pattern:    `sk-[a-zA-Z0-9]{20,}`,
		reasonCode: "OUTPUT_SECRET_OPENAI_KEY",
		reason:     "OpenAI API key detected in output",
	}},
	CatSecretAnthropic: {{
		pattern:    `sk-ant-[a-zA-Z0-9-]{20,}`,
		reasonCode: "OUTPUT_SECRET_ANTHROPIC_KEY",
		reason:     "Anthropic API key detected in output",
	}},
	CatSecretBearer: {{
		pattern:    `(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`,
		reasonCode: "OUTPUT_SECRET_BEARER_TOKEN",
		reason:     "bearer token detected in output",
	}},
	CatPIIEmail: {{
		pattern:    `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		reasonCode: "OUTPUT_PII_EMAIL",
		reason:     "email address detected in output",
	}},
	CatPIIPhone: {{
		pattern:    `(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,
		reasonCode: "OUTPUT_PII_PHONE",
		reason:     "phone number detected in output",
	}},
	CatPIISSN: {{
		pattern:    `\b\d{3}-\d{2}-\d{4}\b`,
		reasonCode: "OUTPUT_PII_SSN",
		reason:     "Social Security Number detected in output",
	}},
	CatPIICreditCard: {{
		pattern:    `\b(?:\d[ -]*?){13,16}\b`,
		reasonCode: "OUTPUT_PII_CREDIT_CARD",
		reason:     "credit card number detected in output",
	}},
	CatPIIIPAddress: {{
		pattern:    `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
		reasonCode: "OUTPUT_PII_IP_ADDRESS",
		reason:     "IP address detected in output",
	}},
	CatPIINPI: {{
		pattern:    `\b\d{10}\b`,
		reasonCode: "OUTPUT_PII_NPI",
		reason:     "National Provider Identifier detected in output",
	}},
	CatPIIIBAN: {{
		pattern:    `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b`,
		reasonCode: "OUTPUT_PII_IBAN",
		reason:     "IBAN detected in output",
	}},
	CatInjection: {
		{
			pattern:    `(?i)(ignore\s+(all\s+)?previous\s+instructions)`,
			reasonCode: "OUTPUT_INJECTION_IGNORE_PREV",
			reason:     "prompt injection pattern detected in output",
		},
		{
			pattern:    `(?i)(system:\s*you\s+are\s+now)`,
			reasonCode: "OUTPUT_INJECTION_IGNORE_PREV",
			reason:     "prompt injection pattern detected in output",
		},
	},
}

// matchToolPattern checks if a tool ID matches a glob-like pattern.
func matchToolPattern(pattern, toolID string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(toolID, pattern[:len(pattern)-1])
	}
	return pattern == toolID
}
