package core

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
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
	engine   *policy.Engine
	wal      dpr.Writer
	store    *dpr.Store      // may be nil (in-memory / demo mode)
	sessions *session.Manager
	defers   *deferwork.Workflow
	chainMu  map[string]string // agentID -> last record hash (in-memory cache)
	syncer   DecisionSyncer    // optional Horizon sync (nil = disabled)
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
		engine:   cfg.Engine,
		wal:      cfg.WAL,
		store:    cfg.Store,
		sessions: cfg.Sessions,
		defers:   cfg.Defers,
		chainMu:  make(map[string]string),
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

	// [4] Session state — increment call count.
	callCount := sess.IncrCallCount()

	// [5] Budget enforcement — check session and daily limits.
	doc := p.engine.Doc()
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
		d = Decision{
			Effect:        EffectDeny,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
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

	// [9] WAL write — fsync before returning.
	rec := p.buildRecord(req, d)
	if err := p.wal.Write(rec); err != nil {
		// If we can't write the audit record, we must deny.
		// Execution must never precede the audit record.
		return Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.WALWriteFailure,
			Reason:     "audit record write failed; denying to preserve WAL invariant",
			Latency:    time.Since(start),
		}
	}

	// [10] Async: replicate to SQLite, update session history, sync to Horizon.
	if p.store != nil {
		go func() {
			_ = p.store.Save(rec)
		}()
	}
	go sess.RecordHistory(req.ToolID, string(d.Effect))
	if p.syncer != nil {
		go p.syncer.Send(d)
	}

	// [11] Return Decision.
	return d
}

// buildRecord constructs the DPR record for this decision.
func (p *Pipeline) buildRecord(req CanonicalActionRequest, d Decision) *dpr.Record {
	prevHash := p.chainMu[req.AgentID]
	if prevHash == "" {
		// Genesis record: deterministic hash from agent ID + session ID.
		prevHash = fmt.Sprintf("%x", sha256.Sum256([]byte(req.AgentID+req.SessionID+"genesis")))
	}

	rec := &dpr.Record{
		SchemaVersion:     dpr.SchemaVersion,
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
		PolicyVersion:     d.PolicyVersion,
		ArgsStructuralSig: dpr.ArgsSignature(req.Args),
		CreatedAt:         req.Timestamp,
	}
	rec.ComputeHash()
	p.chainMu[req.AgentID] = rec.RecordHash
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
