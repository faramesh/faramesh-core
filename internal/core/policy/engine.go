package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Engine holds a compiled policy and evaluates requests against it.
type Engine struct {
	doc                *Doc
	version            string
	programs           []*vm.Program // compiled expr programs, parallel to doc.Rules
	transitionPrograms []*vm.Program // compiled expr programs, parallel to doc.PhaseTransitions
}

const (
	maxExpressionChars         = 1024
	maxExpressionFunctionCalls = 32
	maxExpressionDepth         = 16
	maxExpressionOperators     = 96
)

var (
	defaultRegistryMu       sync.RWMutex
	defaultOperatorRegistry = NewOperatorRegistry()
	defaultSelectorRegistry = NewSelectorRegistry()
)

// DefaultOperatorRegistry returns the process-wide operator registry used by
// policy expression evaluation (compile-time and runtime env injection).
func DefaultOperatorRegistry() *OperatorRegistry {
	defaultRegistryMu.RLock()
	defer defaultRegistryMu.RUnlock()
	return defaultOperatorRegistry
}

// DefaultSelectorRegistry returns the process-wide selector registry used by
// policy expression evaluation (compile-time and runtime env injection).
func DefaultSelectorRegistry() *SelectorRegistry {
	defaultRegistryMu.RLock()
	defer defaultRegistryMu.RUnlock()
	return defaultSelectorRegistry
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
			rid := rule.ID
			if rid == "" {
				rid = fmt.Sprintf("index:%d", i)
			}
			return nil, fmt.Errorf("rule %q: %w", rid, err)
		}
		programs[i] = prog
	}

	transitionPrograms := make([]*vm.Program, len(doc.PhaseTransitions))
	for i, tr := range doc.PhaseTransitions {
		from := strings.TrimSpace(tr.From)
		to := strings.TrimSpace(tr.To)
		if from == "" || to == "" {
			return nil, fmt.Errorf("phase_transition[%d]: from and to are required", i)
		}
		effect := normalizePhaseTransitionEffect(tr.Effect)
		if effect == "" {
			return nil, fmt.Errorf("phase_transition[%d]: invalid effect %q (must be permit_transition or defer)", i, strings.TrimSpace(tr.Effect))
		}
		cond := strings.TrimSpace(tr.Conditions)
		if cond == "" {
			transitionPrograms[i] = nil
			continue
		}
		prog, err := compileExpr(cond, evalEnv(doc, nil))
		if err != nil {
			return nil, fmt.Errorf("phase_transition[%d] %q->%q: %w", i, from, to, err)
		}
		transitionPrograms[i] = prog
	}

	return &Engine{
		doc:                doc,
		version:            version,
		programs:           programs,
		transitionPrograms: transitionPrograms,
	}, nil
}

// EvalContext is the runtime data available to policy conditions.
type EvalContext struct {
	Args       map[string]any `expr:"args"`
	Vars       map[string]any `expr:"vars"`
	Session    SessionCtx     `expr:"session"`
	Tool       ToolCtx        `expr:"tool"`
	ToolID     string         `expr:"tool_name"`
	Principal  *PrincipalCtx  `expr:"principal"`
	Delegation *DelegationCtx `expr:"delegation"`
	Time       TimeCtx        `expr:"time"`
}

// SessionCtx exposes session-level data to policy conditions.
//
// Available in policy when: expressions as:
//
//	session.call_count         — total calls in this session
//	session.history            — array of recent tool calls (newest first)
//	session.cost_usd           — session cost in USD (when CostShield is enabled)
//	session.daily_cost_usd     — daily cost in USD (when CostShield is enabled)
//	session.intent_class       — cached async intent class (empty when unset/expired)
type SessionCtx struct {
	CallCount    int64            `expr:"call_count"`
	History      []map[string]any `expr:"history"` // [{tool, effect, timestamp}, ...]
	CostUSD      float64          `expr:"cost_usd"`
	DailyCostUSD float64          `expr:"daily_cost_usd"`
	IntentClass  string           `expr:"intent_class"`
}

// ToolCtx exposes per-tool metadata declared in the policy tools: block.
//
// Available in policy when: expressions as:
//
//	tool.reversibility         — "irreversible" | "reversible" | "compensatable"
//	tool.blast_radius          — "none" | "local" | "scoped" | "system" | "external"
//	tool.tags                  — array of string tags
type ToolCtx struct {
	Reversibility string   `expr:"reversibility"`
	BlastRadius   string   `expr:"blast_radius"`
	Tags          []string `expr:"tags"`
}

// PrincipalCtx exposes the invoking principal's identity to policy conditions.
//
// Available in policy when: expressions as:
//
//	principal.id               — IDP-verified identity (e.g. "user@company.com")
//	principal.tier             — SaaS tier (free, pro, enterprise)
//	principal.role             — organizational role (analyst, operator, admin)
//	principal.org              — organization identifier
//	principal.verified         — whether identity is IDP-verified
type PrincipalCtx struct {
	ID       string `expr:"id"`
	Tier     string `expr:"tier"`
	Role     string `expr:"role"`
	Org      string `expr:"org"`
	Verified bool   `expr:"verified"`
}

// DelegationCtx exposes the delegation chain to policy conditions.
//
// Available in policy when: expressions as:
//
//	delegation.depth                — delegation chain depth (0 = direct)
//	delegation.origin_agent         — root orchestrator agent ID
//	delegation.origin_org           — root orchestrator organization
//	delegation.agent_identity_verified — all agents in chain verified
type DelegationCtx struct {
	Depth                 int    `expr:"depth"`
	OriginAgent           string `expr:"origin_agent"`
	OriginOrg             string `expr:"origin_org"`
	AgentIdentityVerified bool   `expr:"agent_identity_verified"`
}

// TimeCtx exposes temporal conditions to policy rules.
//
// Available in policy when: expressions as:
//
//	time.hour                — current hour (0-23, UTC)
//	time.weekday             — current day of week (1=Mon, 7=Sun)
//	time.month               — current month (1-12)
//	time.day                 — current day of month (1-31)
type TimeCtx struct {
	Hour    int `expr:"hour"`
	Weekday int `expr:"weekday"`
	Month   int `expr:"month"`
	Day     int `expr:"day"`
}

// EvalResult is returned by Evaluate.
type EvalResult struct {
	Effect     string
	RuleID     string
	ReasonCode string
	Reason     string
}

// PhaseTransitionResult describes a matched phase transition.
type PhaseTransitionResult struct {
	From   string
	To     string
	Effect string
	Reason string
}

// Evaluate runs the first-match-wins evaluation pipeline.
// If no rule matches, the policy's default_effect is applied.
func (e *Engine) Evaluate(toolID string, ctx EvalContext) EvalResult {
	if ctx.Vars == nil {
		ctx.Vars = e.doc.Vars
	}
	if strings.TrimSpace(ctx.ToolID) == "" {
		ctx.ToolID = toolID
	}

	for i, rule := range e.doc.Rules {
		if !matchRule(rule.Match, toolID, ctx.Args) {
			continue
		}
		if e.programs[i] != nil {
			env := evalEnv(e.doc, &ctx)
			out, err := vm.Run(e.programs[i], env)
			if err != nil {
				return evalFailureResult(rule, err)
			}
			if out == nil {
				return evalFailureResult(rule, errors.New("expression produced nil result"))
			}
			matched, ok := out.(bool)
			if !ok {
				return evalFailureResult(rule, fmt.Errorf("expression returned non-bool %T", out))
			}
			if !matched {
				continue
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
		RuleID:     "",
		ReasonCode: unmatchedReasonCode(e.doc.DefaultEffect),
		Reason:     "no rule matched; applying default_effect",
	}
}

// EvaluatePhaseTransition checks phase_transitions for a matching transition from
// fromPhase. Returns the first matched transition in declaration order.
func (e *Engine) EvaluatePhaseTransition(fromPhase string, ctx EvalContext) (PhaseTransitionResult, bool, error) {
	from := strings.TrimSpace(fromPhase)
	if from == "" || len(e.doc.PhaseTransitions) == 0 {
		return PhaseTransitionResult{}, false, nil
	}
	if ctx.Vars == nil {
		ctx.Vars = e.doc.Vars
	}

	for i, tr := range e.doc.PhaseTransitions {
		if strings.TrimSpace(tr.From) != from {
			continue
		}
		if i < len(e.transitionPrograms) && e.transitionPrograms[i] != nil {
			env := evalEnv(e.doc, &ctx)
			out, err := vm.Run(e.transitionPrograms[i], env)
			if err != nil {
				return PhaseTransitionResult{}, false, fmt.Errorf("phase_transition[%d] runtime error: %w", i, err)
			}
			if out == nil {
				return PhaseTransitionResult{}, false, fmt.Errorf("phase_transition[%d] expression produced nil result", i)
			}
			matched, ok := out.(bool)
			if !ok {
				return PhaseTransitionResult{}, false, fmt.Errorf("phase_transition[%d] expression returned non-bool %T", i, out)
			}
			if !matched {
				continue
			}
		}

		effect := normalizePhaseTransitionEffect(tr.Effect)
		if effect == "" {
			return PhaseTransitionResult{}, false, fmt.Errorf("phase_transition[%d] has invalid effect %q", i, strings.TrimSpace(tr.Effect))
		}
		return PhaseTransitionResult{
			From:   strings.TrimSpace(tr.From),
			To:     strings.TrimSpace(tr.To),
			Effect: effect,
			Reason: strings.TrimSpace(tr.Reason),
		}, true, nil
	}

	return PhaseTransitionResult{}, false, nil
}

func evalFailureResult(rule Rule, err error) EvalResult {
	rid := rule.ID
	if rid == "" {
		rid = "unknown"
	}
	return EvalResult{
		Effect:     "deny",
		RuleID:     rid,
		ReasonCode: "EXPR_RUNTIME_ERROR",
		Reason:     fmt.Sprintf("rule expression runtime error (%s): %v", rid, err),
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

func matchRule(m Match, toolID string, args map[string]any) bool {
	if !matchTool(m.Tool, toolID) {
		return false
	}
	return matchNetworkPrimitives(m, args)
}

func matchNetworkPrimitives(m Match, args map[string]any) bool {
	if strings.TrimSpace(m.Host) == "" &&
		strings.TrimSpace(m.Port) == "" &&
		strings.TrimSpace(m.Method) == "" &&
		strings.TrimSpace(m.Path) == "" &&
		len(m.Query) == 0 &&
		len(m.Headers) == 0 {
		return true
	}

	na := extractNetworkArgs(args)

	if strings.TrimSpace(m.Host) != "" && !matchValuePattern(m.Host, na.Host, true) {
		return false
	}
	if strings.TrimSpace(m.Port) != "" && !matchPortPattern(m.Port, na.Port) {
		return false
	}
	if strings.TrimSpace(m.Method) != "" && !matchValuePattern(m.Method, na.Method, true) {
		return false
	}
	if strings.TrimSpace(m.Path) != "" && !matchValuePattern(m.Path, na.Path, false) {
		return false
	}

	for qk, qPattern := range m.Query {
		values, ok := na.Query[qk]
		if !ok || len(values) == 0 {
			return false
		}
		if strings.TrimSpace(qPattern) == "" {
			continue
		}
		matched := false
		for _, v := range values {
			if matchValuePattern(qPattern, v, false) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for hk, hPattern := range m.Headers {
		actual, ok := na.Headers[strings.ToLower(strings.TrimSpace(hk))]
		if !ok {
			return false
		}
		if strings.TrimSpace(hPattern) == "" {
			continue
		}
		if !matchValuePattern(hPattern, actual, false) {
			return false
		}
	}

	return true
}

type networkArgs struct {
	Host    string
	Port    int
	Method  string
	Path    string
	Query   map[string][]string
	Headers map[string]string
}

func extractNetworkArgs(args map[string]any) networkArgs {
	na := networkArgs{
		Host:    strings.TrimSpace(argsString(args, "host")),
		Port:    int(argsNumber(args, "port")),
		Method:  strings.ToUpper(strings.TrimSpace(argsString(args, "method"))),
		Path:    strings.TrimSpace(argsString(args, "path")),
		Query:   make(map[string][]string),
		Headers: make(map[string]string),
	}

	if rawQ := strings.TrimSpace(argsString(args, "raw_query")); rawQ != "" {
		for key, vals := range parseRawQuery(rawQ) {
			na.Query[key] = append(na.Query[key], vals...)
		}
	}

	if raw, ok := args["query"]; ok {
		switch q := raw.(type) {
		case map[string][]string:
			for k, vals := range q {
				if len(vals) == 0 {
					continue
				}
				na.Query[k] = append(na.Query[k], vals...)
			}
		case map[string]string:
			for k, v := range q {
				na.Query[k] = append(na.Query[k], strings.TrimSpace(v))
			}
		case map[string]any:
			for k, v := range q {
				switch typed := v.(type) {
				case []any:
					for _, item := range typed {
						na.Query[k] = append(na.Query[k], strings.TrimSpace(fmt.Sprint(item)))
					}
				case []string:
					for _, item := range typed {
						na.Query[k] = append(na.Query[k], strings.TrimSpace(item))
					}
				default:
					na.Query[k] = append(na.Query[k], strings.TrimSpace(fmt.Sprint(v)))
				}
			}
		}
	}

	if raw, ok := args["headers"]; ok {
		switch h := raw.(type) {
		case map[string]string:
			for k, v := range h {
				key := strings.ToLower(strings.TrimSpace(k))
				if key == "" {
					continue
				}
				na.Headers[key] = strings.TrimSpace(v)
			}
		case map[string]any:
			for k, v := range h {
				key := strings.ToLower(strings.TrimSpace(k))
				if key == "" {
					continue
				}
				na.Headers[key] = strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}

	if rawURL := strings.TrimSpace(argsString(args, "url")); rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil {
			if na.Host == "" {
				na.Host = strings.TrimSpace(u.Hostname())
			}
			if na.Port <= 0 {
				if p := u.Port(); p != "" {
					if parsed, err := strconv.Atoi(p); err == nil {
						na.Port = parsed
					}
				}
			}
			if na.Path == "" {
				na.Path = strings.TrimSpace(u.EscapedPath())
				if na.Path == "" {
					na.Path = strings.TrimSpace(u.Path)
				}
			}
			if len(na.Query) == 0 {
				for key, vals := range u.Query() {
					na.Query[key] = append(na.Query[key], vals...)
				}
			}
		}
	}

	if na.Host != "" {
		if host, port, err := net.SplitHostPort(na.Host); err == nil {
			na.Host = strings.TrimSpace(host)
			if na.Port <= 0 {
				if parsed, err := strconv.Atoi(port); err == nil {
					na.Port = parsed
				}
			}
		}
	}

	if na.Host != "" {
		na.Host = strings.ToLower(strings.Trim(na.Host, "[]"))
	}

	if na.Path == "" {
		na.Path = "/"
	}

	return na
}

func parseRawQuery(raw string) map[string][]string {
	out := make(map[string][]string)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return out
	}
	for k, v := range vals {
		if len(v) == 0 {
			continue
		}
		out[k] = append(out[k], v...)
	}
	return out
}

func matchValuePattern(pattern, value string, caseInsensitive bool) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "" {
		return true
	}
	if value == "" {
		return false
	}
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	if pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, value)
	if err != nil {
		return value == pattern
	}
	return matched
}

func matchPortPattern(selector string, port int) bool {
	if strings.TrimSpace(selector) == "" {
		return true
	}
	if port <= 0 || port > 65535 {
		return false
	}
	for _, token := range strings.Split(selector, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if token == "*" {
			return true
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			if len(parts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if start > end {
				start, end = end, start
			}
			if port >= start && port <= end {
				return true
			}
			continue
		}
		p, err := strconv.Atoi(token)
		if err != nil {
			continue
		}
		if p == port {
			return true
		}
	}
	return false
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
//
//	args_array_len(path) int
//	  Returns the length of an array argument at the given path.
//	  Example: args_array_len("recipients") > 10
//
//	args_array_contains(path, value) bool
//	  Returns true if an array argument contains value.
//	  Example: args_array_contains("recipients", "ceo@company.com")
//
//	args_array_any_match(path, pattern) bool
//	  Returns true if any array element matches a glob pattern.
//	  Example: args_array_any_match("recipients", "*@external.com")
//
//	purpose(expected) bool
//	  Returns true when args.purpose equals expected (case-insensitive).
//	  Example: purpose("refund_processing")
//
//	amount
//	  Alias for numeric args.amount (defaults to 0 when missing/non-numeric).
//
//	cmd
//	  Alias for string args.cmd (defaults to empty string).
//
//	host / path
//	  Aliases for args.host / args.path.
//
//	tool_name
//	  Alias for the current tool ID.
//
//	recipients
//	  Alias for args_array_len("recipients").
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
	sentinelDenyCountWithin := func(seconds int) int { return 0 }
	sentinelArgsArrayLen := func(path string) int { return 0 }
	sentinelArgsArrayContains := func(path, value string) bool { return false }
	sentinelArgsArrayAnyMatch := func(path, pattern string) bool { return false }
	sentinelPurpose := func(expected string) bool { return false }

	// Default zero-value environment (used at compile time for type checking).
	env := map[string]any{
		"vars": vars,
		"args": map[string]any{},
		"session": map[string]any{
			"call_count":     int64(0),
			"history":        []map[string]any{},
			"cost_usd":       float64(0),
			"daily_cost_usd": float64(0),
			"intent_class":   "",
		},
		"tool": map[string]any{
			"reversibility": "",
			"blast_radius":  "",
			"tags":          []string{},
		},
		"principal": map[string]any{
			"id":       "",
			"tier":     "",
			"role":     "",
			"org":      "",
			"verified": false,
		},
		"delegation": map[string]any{
			"depth":                   0,
			"origin_agent":            "",
			"origin_org":              "",
			"agent_identity_verified": false,
		},
		"time": map[string]any{
			"hour":    0,
			"weekday": 0,
			"month":   0,
			"day":     0,
		},
		"amount":                  float64(0),
		"cmd":                     "",
		"host":                    "",
		"path":                    "",
		"tool_name":               "",
		"recipients":              0,
		"purpose":                 sentinelPurpose,
		"history_contains_within": sentinelHistoryContainsWithin,
		"history_sequence":        sentinelHistorySequence,
		"history_tool_count":      sentinelHistoryToolCount,
		"deny_count_within":       sentinelDenyCountWithin,
		"args_array_len":          sentinelArgsArrayLen,
		"args_array_contains":     sentinelArgsArrayContains,
		"args_array_any_match":    sentinelArgsArrayAnyMatch,
		"contains":                func(arr []string, s string) bool { return false },
	}
	if ctx == nil {
		// Compile-time env must include registered operators/selectors or NewEngine
		// cannot compile rules that reference them (Evaluate would skip to default_effect).
		DefaultOperatorRegistry().InjectIntoEnv(env, nil)
		DefaultSelectorRegistry().InjectIntoEnv(env, nil)
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
		"intent_class":   ctx.Session.IntentClass,
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

	// Inject principal context if available.
	if ctx.Principal != nil {
		env["principal"] = map[string]any{
			"id":       ctx.Principal.ID,
			"tier":     ctx.Principal.Tier,
			"role":     ctx.Principal.Role,
			"org":      ctx.Principal.Org,
			"verified": ctx.Principal.Verified,
		}
	}

	// Inject delegation context if available.
	if ctx.Delegation != nil {
		env["delegation"] = map[string]any{
			"depth":                   ctx.Delegation.Depth,
			"origin_agent":            ctx.Delegation.OriginAgent,
			"origin_org":              ctx.Delegation.OriginOrg,
			"agent_identity_verified": ctx.Delegation.AgentIdentityVerified,
		}
	}

	// Inject time context; allow explicit context to make replay deterministic.
	now := time.Now().UTC()
	if ctx.Time.Month >= 1 && ctx.Time.Month <= 12 && ctx.Time.Day >= 1 && ctx.Time.Day <= 31 &&
		ctx.Time.Hour >= 0 && ctx.Time.Hour <= 23 && ctx.Time.Weekday >= 1 && ctx.Time.Weekday <= 7 {
		now = time.Date(2000, time.Month(ctx.Time.Month), ctx.Time.Day, ctx.Time.Hour, 0, 0, 0, time.UTC)
	}
	env["time"] = map[string]any{
		"hour":    now.Hour(),
		"weekday": normalizeExprWeekday(int(now.Weekday())),
		"month":   int(now.Month()),
		"day":     now.Day(),
	}

	// Inject live history helper functions using the actual history snapshot.
	// These closures are re-created per evaluation so they operate on the current
	// session history, not a stale snapshot.
	env["history_contains_within"] = historyContainsWithin(history)
	env["history_sequence"] = historySequence(history)
	env["history_tool_count"] = historyToolCount(history)
	env["deny_count_within"] = denyCountWithin(history)
	env["args_array_len"] = argsArrayLen(ctx.Args)
	env["args_array_contains"] = argsArrayContains(ctx.Args)
	env["args_array_any_match"] = argsArrayAnyMatch(ctx.Args)
	env["amount"] = argsNumber(ctx.Args, "amount")
	env["cmd"] = argsString(ctx.Args, "cmd")
	env["host"] = argsString(ctx.Args, "host")
	env["path"] = argsString(ctx.Args, "path")
	env["tool_name"] = strings.TrimSpace(ctx.ToolID)
	env["recipients"] = argsArrayLen(ctx.Args)("recipients")
	env["purpose"] = purposeMatches(ctx.Args)

	// contains helper: check if a string slice contains a given string.
	env["contains"] = func(arr []string, s string) bool {
		for _, v := range arr {
			if v == s {
				return true
			}
		}
		return false
	}

	// Inject custom operators and data selectors from the default registries.
	// This closes the wiring gap where registered operators/selectors existed
	// but were never visible to expression evaluation.
	DefaultOperatorRegistry().InjectIntoEnv(env, nil)
	DefaultSelectorRegistry().InjectIntoEnv(env, nil)

	return env
}

func normalizeExprWeekday(day int) int {
	if day == 0 {
		return 7
	}
	return day
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

// denyCountWithin returns a function that counts DENY outcomes in the recent
// history window.
func denyCountWithin(history []map[string]any) func(int) int {
	return func(seconds int) int {
		cutoff := time.Now().Unix() - int64(seconds)
		count := 0
		for _, entry := range history {
			ts, ok := entry["timestamp"].(int64)
			if !ok || ts < cutoff {
				continue
			}
			effect, _ := entry["effect"].(string)
			if strings.EqualFold(effect, "DENY") {
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

func argsArrayLen(args map[string]any) func(string) int {
	return func(path string) int {
		arr := arrayAtPath(args, path)
		return len(arr)
	}
}

func argsArrayContains(args map[string]any) func(string, string) bool {
	return func(path, value string) bool {
		arr := arrayAtPath(args, path)
		for _, item := range arr {
			if fmt.Sprint(item) == value {
				return true
			}
		}
		return false
	}
}

func argsArrayAnyMatch(args map[string]any) func(string, string) bool {
	return func(path, pattern string) bool {
		arr := arrayAtPath(args, path)
		for _, item := range arr {
			if matchToolPattern(pattern, fmt.Sprint(item)) {
				return true
			}
		}
		return false
	}
}

func arrayAtPath(args map[string]any, path string) []any {
	if args == nil || path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	var cur any = args
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		next, exists := m[p]
		if !exists {
			return nil
		}
		cur = next
	}
	return toAnySlice(cur)
}

func toAnySlice(v any) []any {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		return arr
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out
}

// compileExpr compiles an expr-lang expression string to bytecode.
func compileExpr(expression string, env map[string]any) (*vm.Program, error) {
	if err := validateExpressionBounds(expression); err != nil {
		return nil, err
	}
	opts := []expr.Option{
		expr.AsBool(),
	}
	if env != nil {
		opts = append(opts, expr.Env(env))
	}
	return expr.Compile(expression, opts...)
}

var (
	funcCallRe       = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	namespacedCallRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	operatorTokenRe  = regexp.MustCompile(`\&\&|\|\||==|!=|<=|>=|<|>|\+|-|\*|/|%`)
)

func validateExpressionBounds(expression string) error {
	exprRunes := []rune(expression)
	if len(exprRunes) > maxExpressionChars {
		return fmt.Errorf("when expression exceeds max chars (%d > %d)", len(exprRunes), maxExpressionChars)
	}

	funcCalls := len(funcCallRe.FindAllStringSubmatch(expression, -1)) + len(namespacedCallRe.FindAllStringSubmatch(expression, -1))
	if funcCalls > maxExpressionFunctionCalls {
		return fmt.Errorf("when expression exceeds max function calls (%d > %d)", funcCalls, maxExpressionFunctionCalls)
	}

	operatorCount := len(operatorTokenRe.FindAllString(expression, -1))
	if operatorCount > maxExpressionOperators {
		return fmt.Errorf("when expression exceeds max operator complexity (%d > %d)", operatorCount, maxExpressionOperators)
	}

	depth, err := expressionDepthHeuristic(expression)
	if err != nil {
		return err
	}
	if depth > maxExpressionDepth {
		return fmt.Errorf("when expression exceeds max nesting depth (%d > %d)", depth, maxExpressionDepth)
	}
	return nil
}

func expressionDepthHeuristic(expression string) (int, error) {
	var (
		maxDepth int
		depth    int
	)
	for _, ch := range expression {
		switch ch {
		case '(', '[', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return 0, errors.New("when expression has unbalanced closing delimiter")
			}
		}
	}
	if depth != 0 {
		return 0, errors.New("when expression has unbalanced delimiters")
	}
	return maxDepth, nil
}

func argsNumber(args map[string]any, key string) float64 {
	if args == nil {
		return 0
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return 0
	}
	switch v := raw.(type) {
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(raw)), 64); err == nil {
		return f
	}
	return 0
}

func argsString(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return ""
	}
	if s, ok := raw.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(raw))
}

func purposeMatches(args map[string]any) func(string) bool {
	actual := strings.TrimSpace(argsString(args, "purpose"))
	return func(expected string) bool {
		expected = strings.TrimSpace(expected)
		if actual == "" || expected == "" {
			return false
		}
		return strings.EqualFold(actual, expected)
	}
}

func normalizePhaseTransitionEffect(raw string) string {
	effect := strings.ToLower(strings.TrimSpace(raw))
	if effect == "" {
		return "permit_transition"
	}
	if effect != "permit_transition" && effect != "defer" {
		return ""
	}
	return effect
}

func unmatchedReasonCode(effect string) string {
	switch strings.ToLower(effect) {
	case "permit", "allow":
		return "UNMATCHED_PERMIT"
	case "deny", "halt":
		return "UNMATCHED_DENY"
	case "defer", "abstain", "pending":
		return "UNMATCHED_DEFER"
	case "shadow":
		return "UNMATCHED_SHADOW"
	default:
		return "UNMATCHED_UNKNOWN"
	}
}
