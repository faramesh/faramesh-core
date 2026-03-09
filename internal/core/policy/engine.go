package policy

import (
	"path"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Engine holds a compiled policy and evaluates requests against it.
type Engine struct {
	doc      *Doc
	version  string
	programs []*vm.Program // compiled expr programs, parallel to doc.Rules
}

// NewEngine compiles the policy doc into an evaluatable engine.
// Compilation happens once at load time; evaluation is ~1μs per rule.
func NewEngine(doc *Doc, version string) (*Engine, error) {
	programs := make([]*vm.Program, len(doc.Rules))
	for i, rule := range doc.Rules {
		if rule.Match.When == "" {
			programs[i] = nil
			continue
		}
		prog, err := compileExpr(rule.Match.When, evalEnv(doc, nil))
		if err != nil {
			return nil, err
		}
		programs[i] = prog
	}
	return &Engine{doc: doc, version: version, programs: programs}, nil
}

// EvalContext is the runtime data available to policy conditions.
type EvalContext struct {
	Args    map[string]any `expr:"args"`
	Vars    map[string]any `expr:"vars"`
	Session SessionCtx     `expr:"session"`
	Tool    ToolCtx        `expr:"tool"`
}

// SessionCtx exposes session-level data to policy conditions.
//
// Available in policy when: expressions as:
//   session.call_count         — total calls in this session
//   session.history            — array of recent tool calls (newest first)
//   session.cost_usd           — session cost in USD (when CostShield is enabled)
//   session.daily_cost_usd     — daily cost in USD (when CostShield is enabled)
type SessionCtx struct {
	CallCount    int64            `expr:"call_count"`
	History      []map[string]any `expr:"history"` // [{tool, effect, timestamp}, ...]
	CostUSD      float64          `expr:"cost_usd"`
	DailyCostUSD float64          `expr:"daily_cost_usd"`
}

// ToolCtx exposes per-tool metadata declared in the policy tools: block.
//
// Available in policy when: expressions as:
//   tool.reversibility         — "irreversible" | "reversible" | "compensatable"
//   tool.blast_radius          — "none" | "local" | "scoped" | "system" | "external"
//   tool.tags                  — array of string tags
type ToolCtx struct {
	Reversibility string   `expr:"reversibility"`
	BlastRadius   string   `expr:"blast_radius"`
	Tags          []string `expr:"tags"`
}

// EvalResult is returned by Evaluate.
type EvalResult struct {
	Effect     string
	RuleID     string
	ReasonCode string
	Reason     string
}

// Evaluate runs the first-match-wins evaluation pipeline.
// If no rule matches, the policy's default_effect is applied.
func (e *Engine) Evaluate(toolID string, ctx EvalContext) EvalResult {
	if ctx.Vars == nil {
		ctx.Vars = e.doc.Vars
	}

	for i, rule := range e.doc.Rules {
		if !matchTool(rule.Match.Tool, toolID) {
			continue
		}
		if e.programs[i] != nil {
			env := evalEnv(e.doc, &ctx)
			out, err := vm.Run(e.programs[i], env)
			if err != nil || out == nil {
				continue
			}
			matched, ok := out.(bool)
			if !ok || !matched {
				continue
			}
		}
		rc := rule.ReasonCode
		if rc == "" {
			switch strings.ToLower(rule.Effect) {
			case "permit", "allow":
				rc = "RULE_PERMIT"
			case "deny", "halt":
				rc = "RULE_DENY"
			case "defer", "abstain", "pending":
				rc = "RULE_DEFER"
			case "shadow":
				rc = "SHADOW_DENY"
			}
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
		RuleID:     "",
		ReasonCode: "UNMATCHED_DENY",
		Reason:     "no rule matched; applying default_effect",
	}
}

// Doc returns the underlying policy document.
func (e *Engine) Doc() *Doc { return e.doc }

// Version returns the policy version hash.
func (e *Engine) Version() string { return e.version }

// matchTool checks whether a rule's tool pattern matches a tool ID.
// Supports glob-style patterns: "stripe/*", "shell/run", "*".
func matchTool(pattern, toolID string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, toolID)
	if err != nil {
		return strings.HasPrefix(toolID, strings.TrimSuffix(pattern, "*"))
	}
	return matched
}

// evalEnv builds the expr-lang environment map for condition evaluation.
// It also injects the built-in history helper functions:
//
//	history_contains_within(tool_pattern, seconds) bool
//	  Returns true if any call matching tool_pattern occurred within the last N seconds.
//	  Example: history_contains_within("http/post", 120)
//
//	history_sequence(tool_a, tool_b, ...) bool
//	  Returns true if the given tools appear in that order in the recent history.
//	  Example: history_sequence("read_file", "shell/exec", "http/post")
//
//	history_tool_count(tool_pattern) int
//	  Returns how many calls to tools matching the pattern are in the history window.
//	  Example: history_tool_count("stripe/*") > 3
func evalEnv(doc *Doc, ctx *EvalContext) map[string]any {
	vars := make(map[string]any)
	for k, v := range doc.Vars {
		vars[k] = v
	}

	// Build sentinel history helper functions for compile-time type checking.
	// These are replaced with closures capturing the live history at eval time.
	sentinelHistoryContainsWithin := func(toolPattern string, seconds int) bool { return false }
	sentinelHistorySequence := func(tools ...string) bool { return false }
	sentinelHistoryToolCount := func(toolPattern string) int { return 0 }

	// Default zero-value environment (used at compile time for type checking).
	env := map[string]any{
		"vars": vars,
		"args": map[string]any{},
		"session": map[string]any{
			"call_count":     int64(0),
			"history":        []map[string]any{},
			"cost_usd":       float64(0),
			"daily_cost_usd": float64(0),
		},
		"tool": map[string]any{
			"reversibility": "",
			"blast_radius":  "",
			"tags":          []string{},
		},
		"history_contains_within": sentinelHistoryContainsWithin,
		"history_sequence":        sentinelHistorySequence,
		"history_tool_count":      sentinelHistoryToolCount,
	}
	if ctx == nil {
		return env
	}

	env["args"] = ctx.Args
	if ctx.Vars != nil {
		env["vars"] = ctx.Vars
	}

	history := ctx.Session.History
	if history == nil {
		history = []map[string]any{}
	}
	env["session"] = map[string]any{
		"call_count":     ctx.Session.CallCount,
		"history":        history,
		"cost_usd":       ctx.Session.CostUSD,
		"daily_cost_usd": ctx.Session.DailyCostUSD,
	}

	tags := ctx.Tool.Tags
	if tags == nil {
		tags = []string{}
	}
	env["tool"] = map[string]any{
		"reversibility": ctx.Tool.Reversibility,
		"blast_radius":  ctx.Tool.BlastRadius,
		"tags":          tags,
	}

	// Inject live history helper functions using the actual history snapshot.
	// These closures are re-created per evaluation so they operate on the current
	// session history, not a stale snapshot.
	env["history_contains_within"] = historyContainsWithin(history)
	env["history_sequence"] = historySequence(history)
	env["history_tool_count"] = historyToolCount(history)

	return env
}

// historyContainsWithin returns a function that tests whether any call to
// a tool matching toolPattern occurred within the last windowSecs seconds.
//
// Policy usage:
//
//	when: "history_contains_within('http/post', 120)"
func historyContainsWithin(history []map[string]any) func(string, int) bool {
	return func(toolPattern string, windowSecs int) bool {
		cutoff := time.Now().Unix() - int64(windowSecs)
		for _, entry := range history {
			ts, ok := entry["timestamp"].(int64)
			if !ok {
				continue
			}
			if ts < cutoff {
				continue
			}
			tool, _ := entry["tool"].(string)
			if matchToolPattern(toolPattern, tool) {
				return true
			}
		}
		return false
	}
}

// historySequence returns a function that tests whether the given tool IDs
// appear in order (not necessarily contiguous) in the session history.
// The history is stored newest-first so we scan backwards for the sequence.
//
// Policy usage:
//
//	when: "history_sequence('read_file', 'shell/exec', 'http/post')"
func historySequence(history []map[string]any) func(...string) bool {
	return func(tools ...string) bool {
		if len(tools) == 0 {
			return true
		}
		// History is newest-first; to match sequence in forward order
		// we reverse and find each tool in order.
		idx := len(tools) - 1 // we scan history oldest-first (reverse) matching in reverse order
		// Build an oldest-first view.
		oldest := make([]string, len(history))
		for i, e := range history {
			tool, _ := e["tool"].(string)
			oldest[len(history)-1-i] = tool
		}
		// Find each tool in order within oldest-first list.
		targetIdx := 0
		for _, tool := range oldest {
			if targetIdx >= len(tools) {
				break
			}
			if matchToolPattern(tools[targetIdx], tool) {
				targetIdx++
			}
		}
		_ = idx
		return targetIdx == len(tools)
	}
}

// historyToolCount returns a function that counts how many calls to tools
// matching toolPattern are in the current history window.
//
// Policy usage:
//
//	when: "history_tool_count('stripe/*') > 3"
func historyToolCount(history []map[string]any) func(string) int {
	return func(toolPattern string) int {
		count := 0
		for _, entry := range history {
			tool, _ := entry["tool"].(string)
			if matchToolPattern(toolPattern, tool) {
				count++
			}
		}
		return count
	}
}

// matchToolPattern matches a tool ID against a glob-style pattern.
// Supports: "*", "prefix/*", "exact/match".
func matchToolPattern(pattern, toolID string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, toolID)
	if err != nil {
		return strings.HasPrefix(toolID, strings.TrimSuffix(pattern, "*"))
	}
	return matched
}

// compileExpr compiles an expr-lang expression string to bytecode.
func compileExpr(expression string, env map[string]any) (*vm.Program, error) {
	opts := []expr.Option{
		expr.AsBool(),
	}
	if env != nil {
		opts = append(opts, expr.Env(env))
	}
	return expr.Compile(expression, opts...)
}
