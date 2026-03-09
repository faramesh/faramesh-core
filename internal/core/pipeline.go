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
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/google/uuid"
)

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
	store    *dpr.Store   // may be nil (in-memory / demo mode)
	sessions *session.Manager
	defers   *deferwork.Workflow
	chainMu  map[string]string // agentID -> last record hash
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
	return &Pipeline{
		engine:   cfg.Engine,
		wal:      cfg.WAL,
		store:    cfg.Store,
		sessions: cfg.Sessions,
		defers:   cfg.Defers,
		chainMu:  make(map[string]string),
	}
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
			ReasonCode: "KILL_SWITCH_ACTIVE",
			Reason:     "agent kill switch is active",
		}, sess, start)
	}

	// [2] Phase check — tool visibility (MVP: skip, always visible).
	// Future: check if tool is in the current workflow phase.

	// [3] Pre-execution scanners (parallel, ~0.1ms total).
	if denied, reason := runScanners(req); denied {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: "SCANNER_DENY",
			Reason:     reason,
		}, sess, start)
	}

	// [4] Session state read.
	callCount := sess.IncrCallCount()

	// [5] History ring buffer read.
	// Exposed to policy conditions via EvalContext.

	// [6] External selector fetch — MVP: skip (no external selectors).

	// [7] Policy evaluation — expr-lang bytecode, first-match-wins.
	ctx := policy.EvalContext{
		Args: req.Args,
		Session: policy.SessionCtx{
			CallCount: callCount,
		},
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
		token := uuid.New().String()[:8]
		reason := result.Reason
		if reason == "" {
			reason = "action requires human approval"
		}
		if _, err := p.defers.Defer(req.AgentID, req.ToolID, reason); err == nil {
			// Reuse the token from the defers workflow.
		}
		// Generate deterministic token from call.
		token = fmt.Sprintf("%x", sha256.Sum256([]byte(req.CallID+req.ToolID)))[:8]
		_, _ = p.defers.Defer(req.AgentID, req.ToolID, reason)
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
			ReasonCode:    "UNKNOWN_EFFECT",
			Reason:        "policy returned unknown effect: " + result.Effect,
			PolicyVersion: p.engine.Version(),
		}
	}

	return p.decide(req, d, sess, start)
}

// decide writes the WAL record and returns the Decision.
// This is the WAL ORDERING INVARIANT implementation:
// no decision is returned until the record is fsynced.
func (p *Pipeline) decide(req CanonicalActionRequest, d Decision, sess *session.State, start time.Time) Decision {
	d.Latency = time.Since(start)

	// [8] Decision is set by caller.

	// [9] WAL write — fsync before returning.
	rec := p.buildRecord(req, d)
	if err := p.wal.Write(rec); err != nil {
		// If we can't write the audit record, we must deny.
		// Execution must never precede the audit record.
		return Decision{
			Effect:     EffectDeny,
			ReasonCode: "WAL_WRITE_FAILURE",
			Reason:     "audit record write failed; denying to preserve WAL invariant",
			Latency:    time.Since(start),
		}
	}

	// [10] Async: replicate to SQLite, update session history.
	if p.store != nil {
		go func() {
			_ = p.store.Save(rec)
		}()
	}
	go sess.RecordHistory(req.ToolID, string(d.Effect))

	// [11] Return Decision.
	return d
}

// buildRecord constructs the DPR record for this decision.
func (p *Pipeline) buildRecord(req CanonicalActionRequest, d Decision) *dpr.Record {
	prevHash := p.chainMu[req.AgentID]
	if prevHash == "" {
		// Genesis record: hash from agent ID + nonce.
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
	destructiveShellRe = regexp.MustCompile(`(?i)(rm\s+-[rf]|mkfs|dd\s+if=|:\(\)\{|fork\s*bomb|>\s*/dev/sd)`)
	secretPatternRe    = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|password\s*=\s*\S+)`)
)

// runScanners runs the pre-execution safety scanners in parallel.
// Returns (true, reason) if the request should be denied, (false, "") otherwise.
func runScanners(req CanonicalActionRequest) (bool, string) {
	argsStr := fmt.Sprintf("%v", req.Args)

	// Shell classifier: dangerous command patterns.
	if strings.HasPrefix(req.ToolID, "shell/") || strings.HasPrefix(req.ToolID, "exec") {
		if cmd, ok := req.Args["cmd"].(string); ok {
			if destructiveShellRe.MatchString(cmd) {
				return true, "scanner detected destructive shell pattern: " + cmd
			}
		}
	}

	// Secret scanner: credential-like values in args.
	if secretPatternRe.MatchString(argsStr) {
		return true, "scanner detected credential-like value in tool arguments"
	}

	return false, ""
}
