// Package postcondition — multi-modal binary scanning.
//
// Detects injection patterns hidden in base64-encoded or binary tool
// arguments. Scans for prompt injection, code injection, and command
// injection in decoded binary payloads.
package postcondition

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// BinaryScanResult holds the result of scanning a binary argument.
type BinaryScanResult struct {
	ArgPath  string   `json:"arg_path"`
	Encoding string   `json:"encoding"` // "base64", "hex", "raw"
	Threats  []Threat `json:"threats,omitempty"`
	Safe     bool     `json:"safe"`
}

// Threat represents a detected injection pattern.
type Threat struct {
	Type     string `json:"type"`     // "prompt_injection", "code_injection", "command_injection"
	Pattern  string `json:"pattern"`  // the matched pattern (truncated)
	Position int    `json:"position"` // byte position in decoded content
	Severity string `json:"severity"` // "critical", "high", "medium"
}

// MultimodalScanner scans binary/encoded arguments for injection patterns.
type MultimodalScanner struct {
	promptInjection  []*regexp.Regexp
	codeInjection    []*regexp.Regexp
	commandInjection []*regexp.Regexp
	maxDecodeSize    int
}

// NewMultimodalScanner creates a multi-modal scanner.
func NewMultimodalScanner() *MultimodalScanner {
	return &MultimodalScanner{
		promptInjection: compilePatterns([]string{
			`(?i)ignore\s+(all\s+)?previous\s+instructions`,
			`(?i)you\s+are\s+now\s+`,
			`(?i)system\s*:\s*`,
			`(?i)forget\s+(everything|all)`,
			`(?i)\[\s*INST\s*\]`,
			`(?i)<<\s*SYS\s*>>`,
		}),
		codeInjection: compilePatterns([]string{
			`(?i)eval\s*\(`,
			`(?i)exec\s*\(`,
			`(?i)__import__\s*\(`,
			`(?i)subprocess\.(call|run|Popen)\s*\(`,
			`(?i)os\.system\s*\(`,
			`(?i)require\s*\(\s*['"]child_process`,
		}),
		commandInjection: compilePatterns([]string{
			`(?i);\s*(rm|cat|curl|wget|nc|bash|sh|python)\s`,
			`(?i)\|\s*(bash|sh|zsh|python|ruby|perl)\s`,
			`(?i)\$\(.*\)`,
			"(?i)`[^`]*`",
			`(?i)&&\s*(rm|curl|wget|nc)\s`,
		}),
		maxDecodeSize: 10 * 1024 * 1024, // 10MB limit
	}
}

// ScanArgs scans all arguments for binary/encoded injection patterns.
func (ms *MultimodalScanner) ScanArgs(args map[string]any) []BinaryScanResult {
	var results []BinaryScanResult
	for path, val := range args {
		s, ok := val.(string)
		if !ok {
			continue
		}
		if result := ms.scanValue(path, s); result != nil {
			results = append(results, *result)
		}
	}
	return results
}

func (ms *MultimodalScanner) scanValue(path, value string) *BinaryScanResult {
	// Try base64 decode.
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
		if len(decoded) > ms.maxDecodeSize {
			return &BinaryScanResult{
				ArgPath:  path,
				Encoding: "base64",
				Safe:     false,
				Threats: []Threat{{
					Type:     "size_exceeded",
					Severity: "high",
					Pattern:  "decoded content exceeds size limit",
				}},
			}
		}
		threats := ms.scanContent(string(decoded))
		return &BinaryScanResult{
			ArgPath:  path,
			Encoding: "base64",
			Threats:  threats,
			Safe:     len(threats) == 0,
		}
	}

	// Try base64url decode.
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil && len(decoded) > 0 && looksLikeBase64(value) {
		threats := ms.scanContent(string(decoded))
		if len(threats) > 0 {
			return &BinaryScanResult{
				ArgPath:  path,
				Encoding: "base64url",
				Threats:  threats,
				Safe:     false,
			}
		}
	}

	return nil
}

func (ms *MultimodalScanner) scanContent(content string) []Threat {
	var threats []Threat

	for _, pattern := range ms.promptInjection {
		if loc := pattern.FindStringIndex(content); loc != nil {
			matchStr := content[loc[0]:loc[1]]
			if len(matchStr) > 100 {
				matchStr = matchStr[:100]
			}
			threats = append(threats, Threat{
				Type:     "prompt_injection",
				Pattern:  matchStr,
				Position: loc[0],
				Severity: "critical",
			})
		}
	}

	for _, pattern := range ms.codeInjection {
		if loc := pattern.FindStringIndex(content); loc != nil {
			matchStr := content[loc[0]:loc[1]]
			if len(matchStr) > 100 {
				matchStr = matchStr[:100]
			}
			threats = append(threats, Threat{
				Type:     "code_injection",
				Pattern:  matchStr,
				Position: loc[0],
				Severity: "high",
			})
		}
	}

	for _, pattern := range ms.commandInjection {
		if loc := pattern.FindStringIndex(content); loc != nil {
			matchStr := content[loc[0]:loc[1]]
			if len(matchStr) > 100 {
				matchStr = matchStr[:100]
			}
			threats = append(threats, Threat{
				Type:     "command_injection",
				Pattern:  matchStr,
				Position: loc[0],
				Severity: "critical",
			})
		}
	}

	return threats
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func looksLikeBase64(s string) bool {
	if len(s) < 4 {
		return false
	}
	validChars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' {
			validChars++
		}
	}
	return float64(validChars)/float64(len(s)) > 0.9 && !strings.Contains(s, " ")
}
