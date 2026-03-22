package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/expr-lang/expr/vm"
)

// AtomicEngine wraps Engine to support lock-free hot-reload and
// evaluation timeouts. The active engine is swapped atomically so
// in-flight evaluations finish on the old engine while new evaluations
// use the newly loaded policy.
type AtomicEngine struct {
	current atomic.Pointer[Engine]
	mu      sync.Mutex // serializes swap operations
}

// NewAtomicEngine creates an AtomicEngine from an initial Engine.
func NewAtomicEngine(initial *Engine) *AtomicEngine {
	a := &AtomicEngine{}
	a.current.Store(initial)
	return a
}

// Get returns the current Engine. This is lock-free and safe for
// concurrent use by hundreds of evaluation goroutines.
func (a *AtomicEngine) Get() *Engine {
	return a.current.Load()
}

// Swap atomically replaces the current engine with a new one.
// The old engine's in-flight evaluations are unaffected.
// Returns the old engine for logging/testing.
func (a *AtomicEngine) Swap(newEngine *Engine) *Engine {
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.current.Swap(newEngine)
	return old
}

// HotReload compiles a new policy doc and swaps it in atomically.
// If compilation fails, the current engine is untouched.
func (a *AtomicEngine) HotReload(doc *Doc, version string) error {
	newEngine, err := NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("hot-reload compile: %w", err)
	}
	a.Swap(newEngine)
	return nil
}

// EvalTimeout is the maximum time allowed for a single rule evaluation.
// If expr-lang takes longer than this, the rule is treated as non-matching
// and a warning is emitted. This prevents ReDoS or pathological expressions
// from blocking the decision pipeline.
const EvalTimeout = 50 * time.Millisecond

// EvaluateWithTimeout runs the first-match-wins evaluation with per-rule
// timeouts. If any rule exceeds EvalTimeout, it's skipped (fail-open for
// that rule, but the overall default is fail-closed via default_effect: deny).
func (e *Engine) EvaluateWithTimeout(ctx context.Context, toolID string, evalCtx EvalContext) EvalResult {
	if evalCtx.Vars == nil {
		evalCtx.Vars = e.doc.Vars
	}

	for i, rule := range e.doc.Rules {
		if !matchTool(rule.Match.Tool, toolID) {
			continue
		}
		if e.programs[i] != nil {
			// Check parent context first.
			select {
			case <-ctx.Done():
				return EvalResult{
					Effect:     "deny",
					ReasonCode: "GOVERNANCE_TIMEOUT",
					Reason:     "evaluation cancelled: " + ctx.Err().Error(),
				}
			default:
			}

			env := evalEnv(e.doc, &evalCtx)
			resultCh := make(chan evalAttempt, 1)
			go func() {
				out, err := vm.Run(e.programs[i], env)
				resultCh <- evalAttempt{out: out, err: err}
			}()

			timer := time.NewTimer(EvalTimeout)
			select {
			case result := <-resultCh:
				timer.Stop()
				if result.err != nil {
					return evalFailureResult(rule, result.err)
				}
				if result.out == nil {
					return evalFailureResult(rule, fmt.Errorf("expression produced nil result"))
				}
				matched, ok := result.out.(bool)
				if !ok {
					return evalFailureResult(rule, fmt.Errorf("expression returned non-bool %T", result.out))
				}
				if !matched {
					continue
				}
			case <-timer.C:
				return EvalResult{
					Effect:     "deny",
					RuleID:     rule.ID,
					ReasonCode: "GOVERNANCE_TIMEOUT",
					Reason:     "rule evaluation timed out",
				}
			case <-ctx.Done():
				timer.Stop()
				return EvalResult{
					Effect:     "deny",
					ReasonCode: "GOVERNANCE_TIMEOUT",
					Reason:     "evaluation cancelled: " + ctx.Err().Error(),
				}
			}
		}
		rc := rule.ReasonCode
		if rc == "" {
			rc = defaultReasonCode(rule.Effect)
		}
		return EvalResult{
			Effect:     rule.Effect,
			RuleID:     rule.ID,
			ReasonCode: rc,
			Reason:     rule.Reason,
		}
	}

	return EvalResult{
		Effect:     e.doc.DefaultEffect,
		ReasonCode: unmatchedReasonCode(e.doc.DefaultEffect),
		Reason:     "no rule matched; applying default_effect",
	}
}

type evalAttempt struct {
	out any
	err error
}

// ValidateRE2 checks that all regex patterns in the policy are valid RE2.
// Go's regexp package only supports RE2, so any pattern that compiles is safe.
// This is called at policy load time to reject PCRE-only patterns that could
// cause issues in other components.
func ValidateRE2(doc *Doc) []string {
	var violations []string
	for _, rule := range doc.Rules {
		if rule.Match.Tool != "" && containsRegex(rule.Match.Tool) {
			if _, err := regexp.Compile(rule.Match.Tool); err != nil {
				violations = append(violations,
					fmt.Sprintf("rule %q: tool pattern %q is not valid RE2: %v", rule.ID, rule.Match.Tool, err))
			}
		}
	}
	// Check cross-session guards.
	for _, g := range doc.CrossSessionGuards {
		if g.ToolPattern != "" && containsRegex(g.ToolPattern) {
			if _, err := regexp.Compile(g.ToolPattern); err != nil {
				violations = append(violations,
					fmt.Sprintf("cross_session_guard: tool_pattern %q is not valid RE2: %v", g.ToolPattern, err))
			}
		}
	}
	return violations
}

// containsRegex heuristically checks if a pattern uses regex syntax
// (not just glob wildcards). Glob patterns with only * are not regex.
func containsRegex(p string) bool {
	for _, c := range p {
		switch c {
		case '(', ')', '[', ']', '{', '}', '+', '?', '|', '^', '$', '.', '\\':
			return true
		}
	}
	return false
}

func defaultReasonCode(effect string) string {
	switch strings.ToLower(effect) {
	case "permit", "allow":
		return "RULE_PERMIT"
	case "deny", "halt":
		return "RULE_DENY"
	case "defer", "abstain", "pending":
		return "RULE_DEFER"
	case "shadow":
		return "SHADOW_DENY"
	default:
		return "RULE_UNKNOWN"
	}
}
