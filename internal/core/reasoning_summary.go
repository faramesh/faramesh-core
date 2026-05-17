package core

import "strings"

const maxReasoningSummaryLen = 2048

const reasoningTruncSuffix = "...[truncated]"

// TruncateReasoningSummary enforces the CAR/DPR reasoning_summary limit.
func TruncateReasoningSummary(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= maxReasoningSummaryLen {
		return s
	}
	keep := maxReasoningSummaryLen - len(reasoningTruncSuffix)
	if keep < 0 {
		keep = 0
	}
	return s[:keep] + reasoningTruncSuffix
}
