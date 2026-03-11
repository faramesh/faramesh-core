package core

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/canonicalize"
	"github.com/faramesh/faramesh-core/internal/core/contextguard"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/postcondition"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/google/uuid"
)

// DecisionSyncer is implemented by any component that wants to receive
// governance decisions in real time (e.g. the Horizon cloud syncer).
// Using an interface here keeps core free of imports from the cloud package.
type DecisionSyncer interface {
	Send(Decision)
}

// Pipeline is the invariant evaluation engine. It runs identically regardless
// of which adapter delivered the CanonicalActionRequest. The adapter's only
// job is to translate its environment into a CAR and act on the Decision.
//
// WAL ORDERING INVARIANT: The WAL write (step 9) happens inside Evaluate()
// before the Decision is returned. If the WAL write fails, DENY is returned.
// Execution must never precede the audit record.
type Pipeline struct {
	engine      *policy.Engine
	wal         dpr.Writer
	store       *dpr.Store      // may be nil (in-memory / demo mode)
	sessions    *session.Manager
	defers      *deferwork.Workflow
	chainMu     map[string]string // agentID -> last record hash (in-memory cache)
	chainLock   sync.Mutex        // protects chainMu
	syncer      DecisionSyncer    // optional Horizon sync (nil = disabled)
	postScanner *postcondition.Scanner // post-execution output scanner (nil = disabled)
	httpClient  *http.Client          // shared HTTP client for context guards
}

// Config holds construction parameters for the Pipeline.
type Config struct {
	Engine   *policy.Engine
	WAL      dpr.Writer
	Store    *dpr.Store // optional
	Sessions *session.Manager
	Defers   *deferwork.Workflow
}

// NewPipeline constructs a Pipeline from a Config.
// If a Store is provided, it seeds the in-memory chain hash cache from the
// latest record per agent so DPR chain continuity survives daemon restarts.
func NewPipeline(cfg Config) *Pipeline {
	if cfg.WAL == nil {
		cfg.WAL = &dpr.NullWAL{}
	}
	if cfg.Sessions == nil {
		cfg.Sessions = session.NewManager()
	}
	if cfg.Defers == nil {
		cfg.Defers = deferwork.NewWorkflow("")
	}
	p := &Pipeline{
		engine:     cfg.Engine,
		wal:        cfg.WAL,
		store:      cfg.Store,
		sessions:   cfg.Sessions,
		defers:     cfg.Defers,
		chainMu:    make(map[string]string),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	// Compile post-condition scanner from policy if post_rules are defined.
	if cfg.Engine != nil && cfg.Engine.Doc() != nil {
		doc := cfg.Engine.Doc()
		if len(doc.PostRules) > 0 {
			scanner, err := postcondition.NewScanner(doc.PostRules, doc.MaxOutputBytes)
			if err == nil {
				p.postScanner = scanner
			}
		}
	}
	// Seed chain hashes from SQLite so the DPR chain is continuous across restarts.
	if cfg.Store != nil {
		if agents, err := cfg.Store.KnownAgents(); err == nil {
			for _, agentID := range agents {
				if h, err := cfg.Store.LastHash(agentID); err == nil && h != "" {
					p.chainMu[agentID] = h
				}
			}
		}
	}
	return p
}

// Evaluate runs the 11-step evaluation pipeline and returns a Decision.
// The WAL record is written and fsynced before this function returns.
func (p *Pipeline) Evaluate(req CanonicalActionRequest) Decision {
	start := time.Now()

	if req.Timestamp.IsZero() {
		req.Timestamp = start
	}
	if req.InterceptAdapter == "" {
		req.InterceptAdapter = "sdk"
	}

	// [0] Canonicalize args (CAR v1.0): NFKC normalization, confusable mapping,
	// null stripping, float 6-significant-figure rounding, string trimming.
	req.Args = canonicalize.Args(req.Args)

	// [0.1] Canonicalize tool ID: apply the same NFKC + confusable mapping
	// to prevent Unicode spoofing attacks on tool identifiers.
	req.ToolID = canonicalize.ToolID(req.ToolID)

	// [1] Kill switch check — nanoseconds, no network.
	sess := p.sessions.Get(req.AgentID)
	if sess.IsKilled() {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.KillSwitchActive,
			Reason:     "agent kill switch is active",
		}, sess, start)
	}

	// [2] Phase check — tool visibility.
	// Future: check if tool is in the current workflow phase.

	// [3] Pre-execution scanners (parallel, ~0.1ms total).
	if denied, code, reason := runScanners(req); denied {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: code,
			Reason:     reason,
		}, sess, start)
	}

	// [3.1] Delegation scope check — ensure delegated calls are within scope.
	if req.Delegation != nil && req.Delegation.Len() > 0 {
		if !req.Delegation.ToolInScope(req.ToolID) {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.DelegationExceedsAuthority,
				Reason:     fmt.Sprintf("tool %q not in delegation scope", req.ToolID),
			}, sess, start)
		}
	}

	// [3.2] Context guard check — verify external context freshness.
	doc := p.engine.Doc()
	if len(doc.ContextGuards) > 0 {
		guardResult := contextguard.Check(doc.ContextGuards, p.httpClient)
		if !guardResult.Passed {
			effect := EffectDeny
			if strings.EqualFold(guardResult.Effect, "defer") {
				effect = EffectDefer
			}
			return p.decide(req, Decision{
				Effect:     effect,
				ReasonCode: guardResult.ReasonCode,
				Reason:     guardResult.Reason,
			}, sess, start)
		}
	}

	// [4] Session state — increment call count.
	callCount := sess.IncrCallCount()

	// [5] Budget enforcement — check session and daily limits.
	if doc == nil {
		doc = p.engine.Doc()
	}
	if doc.Budget != nil {
		if denied, code, reason := p.checkBudget(req.AgentID, doc.Budget, callCount); denied {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start)
		}
	}

	// [6] History ring buffer read — build history context for conditions.
	history := sess.History()

	// [7] Tool metadata lookup — for tool.* condition surface.
	toolMeta := policy.ToolCtx{}
	if doc.Tools != nil {
		if t, ok := doc.Tools[req.ToolID]; ok {
			toolMeta = policy.ToolCtx{
				Reversibility: t.Reversibility,
				BlastRadius:   t.BlastRadius,
				Tags:          t.Tags,
			}
		}
	}

	// [8] Policy evaluation — expr-lang bytecode, first-match-wins.
	// Build session history entries for condition evaluation.
	historyEntries := make([]map[string]any, len(history))
	for i, h := range history {
		historyEntries[i] = map[string]any{
			"tool":      h.ToolID,
			"effect":    h.Effect,
			"timestamp": h.Timestamp.Unix(),
		}
	}

	ctx := policy.EvalContext{
		Args: req.Args,
		Session: policy.SessionCtx{
			CallCount: callCount,
			History:   historyEntries,
		},
		Tool: toolMeta,
	}

	// Wire principal context if present in the request.
	if req.Principal != nil {
		ctx.Principal = &policy.PrincipalCtx{
			ID:       req.Principal.ID,
			Tier:     req.Principal.Tier,
			Role:     req.Principal.Role,
			Org:      req.Principal.Org,
			Verified: req.Principal.Verified,
		}
	}

	// Wire delegation context if present in the request.
	if req.Delegation != nil {
		ctx.Delegation = &policy.DelegationCtx{
			Depth:                  req.Delegation.Depth(),
			OriginAgent:            req.Delegation.OriginAgent(),
			OriginOrg:              req.Delegation.OriginOrg(),
			AgentIdentityVerified:  req.Delegation.AllIdentitiesVerified(),
		}
	}

	result := p.engine.Evaluate(req.ToolID, ctx)

	var d Decision
	switch strings.ToLower(result.Effect) {
	case "permit", "allow":
		d = Decision{
			Effect:        EffectPermit,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
			PolicyVersion: p.engine.Version(),
		}
	case "deny", "halt":
		// Generate an opaque denial token — keyed to call context, not to the
		// rule that matched, so agents cannot reverse-engineer policy structure.
		denialTok := fmt.Sprintf("%x", sha256.Sum256([]byte(req.CallID+req.ToolID+req.AgentID+result.RuleID)))[:16]
		d = Decision{
			Effect:        EffectDeny,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
			DenialToken:   denialTok,
			PolicyVersion: p.engine.Version(),
		}
	case "defer", "abstain", "pending":
		reason := result.Reason
		if reason == "" {
			reason = "action requires human approval"
		}
		// Generate deterministic token from call ID — single Defer() call (no double-registration).
		token := fmt.Sprintf("%x", sha256.Sum256([]byte(req.CallID+req.ToolID)))[:8]
		// Register with the DEFER workflow exactly once.
		handle, err := p.defers.DeferWithToken(token, req.AgentID, req.ToolID, reason)
		if err != nil || handle == nil {
			// If a handle with this token already exists (duplicate call), reuse the token.
			_ = handle
		}
		d = Decision{
			Effect:        EffectDefer,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        reason,
			DeferToken:    token,
			PolicyVersion: p.engine.Version(),
		}
	case "shadow":
		d = Decision{
			Effect:        EffectShadow,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
			PolicyVersion: p.engine.Version(),
		}
	default:
		d = Decision{
			Effect:        EffectDeny,
			ReasonCode:    reasons.UnknownEffect,
			Reason:        "policy returned unknown effect: " + result.Effect,
			PolicyVersion: p.engine.Version(),
		}
	}

	return p.decide(req, d, sess, start)
}

// checkBudget returns (true, code, reason) if the budget is exceeded.
func (p *Pipeline) checkBudget(agentID string, budget *policy.Budget, callCount int64) (bool, string, string) {
	if budget.MaxCalls > 0 && callCount > budget.MaxCalls {
		return true, reasons.SessionToolLimit,
			fmt.Sprintf("session call limit reached (%d/%d)", callCount, budget.MaxCalls)
	}
	// Cost-based limits use the session cost tracked in session.State.
	sess := p.sessions.Get(agentID)
	if budget.SessionUSD > 0 {
		cost := sess.CurrentCostUSD()
		if cost >= budget.SessionUSD {
			return true, reasons.BudgetSessionExceeded,
				fmt.Sprintf("session cost limit reached ($%.4f/$%.4f)", cost, budget.SessionUSD)
		}
	}
	if budget.DailyUSD > 0 {
		cost := sess.DailyCostUSD()
		if cost >= budget.DailyUSD {
			return true, reasons.BudgetDailyExceeded,
				fmt.Sprintf("daily cost limit reached ($%.4f/$%.4f)", cost, budget.DailyUSD)
		}
	}
	return false, "", ""
}

// decide writes the WAL record and returns the Decision.
// This is the WAL ORDERING INVARIANT implementation:
// no decision is returned until the record is fsynced.
func (p *Pipeline) decide(req CanonicalActionRequest, d Decision, sess *session.State, start time.Time) Decision {
	d.Latency = time.Since(start)

	// Record metrics.
	observe.Default.RecordDecision(string(d.Effect), d.ReasonCode, d.Latency)

	// [9] WAL write — fsync before returning.
	rec := p.buildRecord(req, d)
	d.DPRRecordID = rec.RecordID
	if err := p.wal.Write(rec); err != nil {
		observe.Default.RecordWALWrite(false)
		// If we can't write the audit record, we must deny.
		// Execution must never precede the audit record.
		return Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.WALWriteFailure,
			Reason:     "audit record write failed; denying to preserve WAL invariant",
			Latency:    time.Since(start),
		}
	}
	observe.Default.RecordWALWrite(true)

	// [10] Async: replicate to SQLite, update session history, sync to Horizon.
	// For PERMIT decisions: record cost against the session and daily accumulators
	// using the tool's declared cost_usd from the policy. This closes the gap
	// where sess.AddCost was never called, making USD budget enforcement inert.
	if p.store != nil {
		go func() {
			_ = p.store.Save(rec)
		}()
	}
	go sess.RecordHistory(req.ToolID, string(d.Effect))
	if d.Effect == EffectPermit || d.Effect == EffectShadow {
		go p.accountCost(req.AgentID, req.ToolID, sess)
	}
	if p.syncer != nil {
		go p.syncer.Send(d)
	}

	// [11] Return Decision.
	return d
}

// accountCost looks up the declared cost_usd for the tool and records it.
// Called asynchronously after a PERMIT so it does not add latency.
func (p *Pipeline) accountCost(agentID, toolID string, sess *session.State) {
	doc := p.engine.Doc()
	if doc.Tools == nil {
		return
	}
	t, ok := doc.Tools[toolID]
	if !ok || t.CostUSD <= 0 {
		return
	}
	sess.AddCost(t.CostUSD)
}

// buildRecord constructs the DPR record for this decision.
func (p *Pipeline) buildRecord(req CanonicalActionRequest, d Decision) *dpr.Record {
	p.chainLock.Lock()
	prevHash := p.chainMu[req.AgentID]
	if prevHash == "" {
		// Genesis record: deterministic hash from agent ID + session ID.
		prevHash = fmt.Sprintf("%x", sha256.Sum256([]byte(req.AgentID+req.SessionID+"genesis")))
	}

	rec := &dpr.Record{
		SchemaVersion:     dpr.SchemaVersion,
		CARVersion:        CARVersion,
		RecordID:          uuid.New().String(),
		PrevRecordHash:    prevHash,
		AgentID:           req.AgentID,
		SessionID:         req.SessionID,
		ToolID:            req.ToolID,
		InterceptAdapter:  req.InterceptAdapter,
		Effect:            string(d.Effect),
		MatchedRuleID:     d.RuleID,
		ReasonCode:        d.ReasonCode,
		Reason:            d.Reason,
		DenialToken:       d.DenialToken,
		IncidentCategory:  d.IncidentCategory,
		IncidentSeverity:  d.IncidentSeverity,
		PolicyVersion:     d.PolicyVersion,
		ArgsStructuralSig: dpr.ArgsSignature(req.Args),
		CreatedAt:         req.Timestamp,
	}

	// Populate principal hash if available.
	if req.Principal != nil && req.Principal.ID != "" {
		rec.PrincipalIDHash = fmt.Sprintf("%x",
			sha256.Sum256([]byte(req.Principal.ID)))[:16]
	}

	// Store FPL version from current policy.
	if doc := p.engine.Doc(); doc != nil {
		rec.FPLVersion = doc.FarameshVersion
	}

	rec.ComputeHash()
	p.chainMu[req.AgentID] = rec.RecordHash
	p.chainLock.Unlock()
	return rec
}

// SetHorizonSyncer attaches a DecisionSyncer. Every governance decision will
// be forwarded to it after the WAL write. Safe to call before or after Run().
func (p *Pipeline) SetHorizonSyncer(s DecisionSyncer) {
	p.syncer = s
}

// DeferWorkflow returns the DEFER workflow for approve/deny operations.
func (p *Pipeline) DeferWorkflow() *deferwork.Workflow {
	return p.defers
}

// SessionManager returns the session manager.
func (p *Pipeline) SessionManager() *session.Manager {
	return p.sessions
}

// ScanOutput runs post-execution output scanning on a tool's output.
// Adapters call this after a PERMIT'd tool completes, before returning
// the output to the agent's context. Returns the scan result which may
// contain redacted output or a denial.
func (p *Pipeline) ScanOutput(toolID, output string) postcondition.ScanResult {
	if p.postScanner == nil {
		return postcondition.ScanResult{Outcome: postcondition.OutcomePass, Output: output}
	}
	return p.postScanner.Scan(toolID, output)
}

// scanner patterns for pre-execution safety checks.
var (
	destructiveShellRe = regexp.MustCompile(`(?i)(rm\s+-[rf]+|mkfs|dd\s+if=|:\(\)\{|>\s*/dev/sd|shred\s+)`)
	secretPatternRe    = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|password\s*=\s*\S+|api[_-]?key\s*=\s*\S+)`)
	pathTraversalRe    = regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e|%252e%252e)`)
	sqlInjectionRe     = regexp.MustCompile(`(?i)(('|")\s*(;|--|\/\*|OR\s+1\s*=\s*1|DROP\s+TABLE|UNION\s+SELECT))`)
	codeExecRe         = regexp.MustCompile(`(?i)(\beval\s*\(|\bexec\s*\(|__import__\s*\(|\bsubprocess\b)`)
	sensitivePathRe    = regexp.MustCompile(`(?i)(\.env$|\.pem$|id_rsa|credentials|\.secret|config\.yaml$|\.key$|\.p12$|/etc/passwd|/etc/shadow)`)
)

// runScanners runs the pre-execution safety scanners.
// Returns (true, reasonCode, reason) if the request should be denied.
func runScanners(req CanonicalActionRequest) (bool, string, string) {
	argsStr := fmt.Sprintf("%v", req.Args)

	// Shell classifier: dangerous command patterns.
	if strings.HasPrefix(req.ToolID, "shell/") || strings.Contains(req.ToolID, "exec") {
		if cmd, ok := req.Args["cmd"].(string); ok {
			if destructiveShellRe.MatchString(cmd) {
				return true, reasons.ShellClassifierRmRf,
					"scanner detected destructive shell pattern: " + cmd
			}
		}
	}

	// Path traversal detection.
	if pathTraversalRe.MatchString(argsStr) {
		return true, reasons.PathTraversal,
			"scanner detected path traversal pattern in arguments"
	}

	// SQL injection detection.
	if sqlInjectionRe.MatchString(argsStr) {
		return true, reasons.SQLInjection,
			"scanner detected SQL injection pattern in arguments"
	}

	// Code execution in arguments.
	if codeExecRe.MatchString(argsStr) {
		return true, reasons.CodeExecutionInArgs,
			"scanner detected code execution pattern in arguments"
	}

	// Sensitive file path patterns.
	if sensitivePathRe.MatchString(argsStr) {
		return true, reasons.SensitiveFilePath,
			"scanner detected sensitive file path in arguments"
	}

	// Secret/credential pattern detection.
	if secretPatternRe.MatchString(argsStr) {
		return true, reasons.HighEntropySecret,
			"scanner detected credential-like value in tool arguments"
	}

	return false, "", ""
}
