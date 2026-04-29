// Package contextguard implements context freshness verification.
// Before high-stakes actions, guards verify that the agent's external
// context sources are fresh, complete, and consistent.
//
// This implements Layer 13.1 from the Faramesh architecture spec:
// "Context Freshness Guard — the primitive nobody else has."
package contextguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// Result is the outcome of a context guard check.
type Result struct {
	Passed     bool   `json:"passed"`
	Effect     string `json:"effect"` // "deny" or "defer" when failed
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
	Source     string `json:"source"`
}

// Check evaluates all context guards defined in the policy.
// Returns the first failing guard result, or a passing result if all pass.
func Check(guards []policy.ContextGuard, client *http.Client) Result {
	if len(guards) == 0 {
		return Result{Passed: true}
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	for _, guard := range guards {
		result := checkGuard(guard, client)
		if !result.Passed {
			return result
		}
	}
	return Result{Passed: true}
}

func checkGuard(guard policy.ContextGuard, client *http.Client) Result {
	if guard.Endpoint == "" {
		return Result{Passed: true, Source: guard.Source}
	}

	resp, err := client.Get(guard.Endpoint)
	if err != nil {
		return Result{
			Passed:     false,
			Effect:     effectOrDefault(guard.OnMissing, "deny"),
			ReasonCode: "CONTEXT_TIMEOUT",
			Reason:     fmt.Sprintf("context source %q unreachable: %v", guard.Source, err),
			Source:     guard.Source,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{
			Passed:     false,
			Effect:     effectOrDefault(guard.OnMissing, "deny"),
			ReasonCode: "CONTEXT_MISSING",
			Reason:     fmt.Sprintf("context source %q returned status %d", guard.Source, resp.StatusCode),
			Source:     guard.Source,
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return Result{
			Passed:     false,
			Effect:     effectOrDefault(guard.OnMissing, "deny"),
			ReasonCode: "CONTEXT_MISSING",
			Reason:     fmt.Sprintf("context source %q: failed to read body: %v", guard.Source, err),
			Source:     guard.Source,
		}
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return Result{
			Passed:     false,
			Effect:     effectOrDefault(guard.OnMissing, "deny"),
			ReasonCode: "CONTEXT_MISSING",
			Reason:     fmt.Sprintf("context source %q: invalid JSON response", guard.Source),
			Source:     guard.Source,
		}
	}

	// Check required fields.
	for _, field := range guard.RequiredFields {
		if _, ok := data[field]; !ok {
			return Result{
				Passed:     false,
				Effect:     effectOrDefault(guard.OnMissing, "deny"),
				ReasonCode: "CONTEXT_MISSING",
				Reason:     fmt.Sprintf("context source %q: missing required field %q", guard.Source, field),
				Source:     guard.Source,
			}
		}
	}

	// Check freshness via timestamp field if max_age_seconds is set.
	if guard.MaxAgeSecs > 0 {
		ts, ok := data["updated_at"]
		if !ok {
			ts, ok = data["timestamp"]
		}
		if ok {
			if tsStr, isStr := ts.(string); isStr {
				t, err := time.Parse(time.RFC3339, tsStr)
				if err == nil {
					age := time.Since(t)
					if age > time.Duration(guard.MaxAgeSecs)*time.Second {
						return Result{
							Passed:     false,
							Effect:     effectOrDefault(guard.OnStale, "defer"),
							ReasonCode: "CONTEXT_STALE",
							Reason: fmt.Sprintf("context source %q: data is %v old (max %ds)",
								guard.Source, age.Round(time.Second), guard.MaxAgeSecs),
							Source: guard.Source,
						}
					}
				}
			}
		}
	}

	return Result{Passed: true, Source: guard.Source}
}

func effectOrDefault(effect, fallback string) string {
	if effect != "" {
		return effect
	}
	return fallback
}
