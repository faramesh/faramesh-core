package core

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/callbacks"
	"github.com/faramesh/faramesh-core/internal/core/canonicalize"
	"github.com/faramesh/faramesh-core/internal/core/contextguard"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/degraded"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/phases"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/postcondition"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/sandbox"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/core/standing"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
	"github.com/faramesh/faramesh-core/internal/core/webhook"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DecisionSyncer is implemented by any component that wants to receive
// governance decisions in real time (e.g. the Horizon cloud syncer).
// Using an interface here keeps core free of imports from the cloud package.
type DecisionSyncer interface {
	Send(Decision)
}

// PrincipalRevocationChecker checks if a principal is revoked.
type PrincipalRevocationChecker interface {
	IsRevoked(principalID string) bool
}

// PrincipalElevationResolver resolves active principal elevation grants.
type PrincipalElevationResolver interface {
	ActiveGrant(principalID string) *principal.ElevationGrant
}

// WorkloadIdentityDetector can resolve a workload principal identity.
type WorkloadIdentityDetector interface {
	Identity(ctx context.Context) (*principal.Identity, error)
}

// Pipeline is the invariant evaluation engine. It runs identically regardless
// of which adapter delivered the CanonicalActionRequest. The adapter's only
// job is to translate its environment into a CAR and act on the Decision.
//
// WAL ORDERING INVARIANT: The WAL write (step 9) happens inside Evaluate()
// before the Decision is returned. If the WAL write fails, DENY is returned.
// Execution must never precede the audit record.
type Pipeline struct {
	engine            *policy.AtomicEngine
	wal               dpr.Writer
	store             dpr.StoreBackend // may be nil (in-memory / demo mode)
	dprQueue          jobs.DPRQueue
	sessions          *session.Manager
	sessionGovernor   *session.Governor
	defers            *deferwork.Workflow
	chainMu           map[string]string      // agentID -> last record hash (in-memory cache)
	chainLock         sync.Mutex             // protects chainMu
	syncer            DecisionSyncer         // optional Horizon sync (nil = disabled)
	postScanner       *postcondition.Scanner // post-execution output scanner (nil = disabled)
	httpClient        *http.Client           // shared HTTP client for context guards
	webhooks          *webhook.Sender
	degraded          *degraded.Manager
	subPolicies       *multiagent.SubPolicyManager
	routingGovernor   *multiagent.RoutingGovernor
	loopGovernor      *multiagent.LoopGovernor
	aggGovernor       *multiagent.AggregationGovernor
	crossSession      *crossSessionGuardTracker
	callbacks         callbacks.Dispatcher
	revocations       PrincipalRevocationChecker
	elevations        PrincipalElevationResolver
	workloadIdentity  WorkloadIdentityDetector
	credentialRouter  *credential.Router
	intentClassifier  IntentClassifier
	provenance        observe.ArgProvenanceTracker
	phaseManager      *phases.PhaseManager
	runtimeMode       RuntimeMode
	bootstrap         *BootstrapEnforcer
	toolInventory     *toolinventory.Store
	policySourceType  string
	policySourceID    string
	strictModelVerify bool
	hmacKey           []byte
	signingPrivKey    []byte
	signingPubKey     []byte
	log               *zap.Logger
	artifacts         atomic.Value // *policyArtifacts
	callChainMu       sync.Mutex
	activeCallChains  map[string]struct{}
	modelMu           sync.RWMutex
	models            map[string]ModelRegistration
	budgetMu          sync.Mutex
	budgetManagers    map[string]*multiagent.BudgetManager
	standing          *standing.Registry
}

type policyArtifacts struct {
	engine      *policy.Engine
	toolSchemas *policy.ToolSchemaRegistry
	postScanner *postcondition.Scanner
}

// RuntimeStatus is a lightweight snapshot of governance runtime health.
type RuntimeStatus struct {
	PolicyLoaded   bool
	PolicyVersion  string
	DPRHealthy     bool
	ActiveSessions int
	TrustLevel     string
}

// ToolRuntimeMeta is a runtime view of policy-declared tool characteristics.
type ToolRuntimeMeta struct {
	ToolID        string
	Reversibility string
	BlastRadius   string
	Tags          []string
}

// CredentialBrokerToolDiagnostic describes broker behavior for one policy tool.
type CredentialBrokerToolDiagnostic struct {
	ToolID         string   `json:"tool_id"`
	Tags           []string `json:"tags,omitempty"`
	BrokerEnabled  bool     `json:"broker_enabled"`
	Required       bool     `json:"required"`
	Scope          string   `json:"scope,omitempty"`
	MatchedRoute   string   `json:"matched_route,omitempty"`
	Backend        string   `json:"backend,omitempty"`
	UsesFallback   bool     `json:"uses_fallback,omitempty"`
	RouteAvailable bool     `json:"route_available"`
}

// CredentialBrokerDiagnostics provides a control-plane snapshot of broker routing.
type CredentialBrokerDiagnostics struct {
	RouterConfigured   bool                             `json:"router_configured"`
	Backends           []string                         `json:"backends,omitempty"`
	FallbackBackend    string                           `json:"fallback_backend,omitempty"`
	Routes             map[string]string                `json:"routes,omitempty"`
	ToolCount          int                              `json:"tool_count"`
	BrokerEnabledCount int                              `json:"broker_enabled_count"`
	RequiredCount      int                              `json:"required_count"`
	Tools              []CredentialBrokerToolDiagnostic `json:"tools"`
}

const (
	minExecutionTimeoutMS = 50
	maxExecutionTimeoutMS = 60 * 60 * 1000

	// policyEvalAggregateTimeout caps wall-clock time for the entire policy
	// evaluation (all rules until first match). It must exceed policy.EvalTimeout
	// so per-rule expr evaluation can complete under goroutine scheduling load;
	// each rule is still bounded by policy.EvalTimeout inside AtomicEngine.
	policyEvalAggregateTimeout = 10 * policy.EvalTimeout
)

// Config holds construction parameters for the Pipeline.
type Config struct {
	Engine                  *policy.AtomicEngine
	WAL                     dpr.Writer
	Store                   dpr.StoreBackend // optional
	DPRQueue                jobs.DPRQueue    // optional async persistence queue
	Sessions                *session.Manager
	SessionGovernor         *session.Governor
	Defers                  *deferwork.Workflow
	Webhooks                *webhook.Sender
	Degraded                *degraded.Manager
	SubPolicies             *multiagent.SubPolicyManager
	RoutingGovernor         *multiagent.RoutingGovernor
	LoopGovernor            *multiagent.LoopGovernor
	AggregationGov          *multiagent.AggregationGovernor
	Callbacks               callbacks.Dispatcher
	Revocations             PrincipalRevocationChecker
	Elevations              PrincipalElevationResolver
	WorkloadIdentity        WorkloadIdentityDetector
	CredentialRouter        *credential.Router
	IntentClassifier        IntentClassifier
	Provenance              observe.ArgProvenanceTracker
	PhaseManager            *phases.PhaseManager
	RuntimeMode             RuntimeMode
	Bootstrap               *BootstrapEnforcer
	ToolInventory           *toolinventory.Store
	PolicySourceType        string
	PolicySourceID          string
	StrictModelVerification bool
	HMACKey                 []byte
	SigningPrivKey          []byte
	SigningPubKey           []byte
	UseJCSCanonicalization  bool
	Log                     *zap.Logger
	Standing                *standing.Registry
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
	if cfg.SessionGovernor == nil {
		cfg.SessionGovernor = session.NewGovernor()
	}
	if cfg.Defers == nil {
		cfg.Defers = deferwork.NewWorkflow("")
	}
	if cfg.RuntimeMode == "" {
		cfg.RuntimeMode = RuntimeModeEnforce
	}
	if len(cfg.HMACKey) > 0 {
		cfg.Defers.SetApprovalHMACKey(cfg.HMACKey)
	}
	stReg := cfg.Standing
	if stReg == nil {
		stReg = standing.NewRegistry()
	}
	p := &Pipeline{
		engine:            cfg.Engine,
		wal:               cfg.WAL,
		store:             cfg.Store,
		dprQueue:          cfg.DPRQueue,
		sessions:          cfg.Sessions,
		sessionGovernor:   cfg.SessionGovernor,
		defers:            cfg.Defers,
		chainMu:           make(map[string]string),
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		webhooks:          cfg.Webhooks,
		degraded:          cfg.Degraded,
		subPolicies:       cfg.SubPolicies,
		routingGovernor:   cfg.RoutingGovernor,
		loopGovernor:      cfg.LoopGovernor,
		aggGovernor:       cfg.AggregationGov,
		crossSession:      newCrossSessionGuardTracker(),
		callbacks:         cfg.Callbacks,
		revocations:       cfg.Revocations,
		elevations:        cfg.Elevations,
		workloadIdentity:  cfg.WorkloadIdentity,
		credentialRouter:  cfg.CredentialRouter,
		intentClassifier:  cfg.IntentClassifier,
		provenance:        cfg.Provenance,
		phaseManager:      cfg.PhaseManager,
		runtimeMode:       cfg.RuntimeMode,
		bootstrap:         cfg.Bootstrap,
		toolInventory:     cfg.ToolInventory,
		policySourceType:  cfg.PolicySourceType,
		policySourceID:    cfg.PolicySourceID,
		strictModelVerify: cfg.StrictModelVerification,
		hmacKey:           cfg.HMACKey,
		signingPrivKey:    cfg.SigningPrivKey,
		signingPubKey:     cfg.SigningPubKey,
		log:               cfg.Log,
		activeCallChains:  make(map[string]struct{}),
		models:            make(map[string]ModelRegistration),
		budgetManagers:    make(map[string]*multiagent.BudgetManager),
		standing:          stReg,
	}
	if p.log == nil {
		p.log = zap.NewNop()
	}

	// Configure DPR canonicalization mode globally for the dpr package.
	if cfg.UseJCSCanonicalization {
		dpr.UseJCSCanonicalization = true
	}
	p.artifacts.Store(buildPolicyArtifacts(currentEngine(cfg.Engine)))
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
	// [1.7] Best-effort: compare SQLite-seeded chain tips with the durable WAL.
	// Mismatch is logged only; SQLite seed remains authoritative for in-memory cache.
	if w, ok := cfg.WAL.(*dpr.WAL); ok && cfg.Store != nil {
		walTips, err := w.ReplayValidatedFinalHashes()
		if err != nil {
			p.log.Warn("dpr wal replay for chain reconciliation failed", zap.Error(err))
		} else {
			for agent, walHash := range walTips {
				sqHash := p.chainMu[agent]
				if sqHash == "" || walHash == "" || sqHash == walHash {
					continue
				}
				p.log.Warn("dpr chain tip mismatch: sqlite last_hash differs from wal replay (using sqlite seed)",
					zap.String("agent_id", agent),
					zap.String("sqlite_record_hash", sqHash),
					zap.String("wal_record_hash", walHash))
			}
		}
	}
	if cfg.RoutingGovernor != nil {
		if eng := currentEngine(cfg.Engine); eng != nil && eng.Doc() != nil {
			p.syncRoutingFromPolicy(eng.Doc())
		}
	}
	return p
}

func buildPolicyArtifacts(engine *policy.Engine) *policyArtifacts {
	art := &policyArtifacts{
		engine:      engine,
		toolSchemas: policy.NewToolSchemaRegistry(),
	}
	if engine == nil || engine.Doc() == nil {
		return art
	}
	doc := engine.Doc()
	for toolID, ts := range doc.ToolSchemas {
		_ = art.toolSchemas.Register(policy.ToolSchemaEntry{
			ToolID:        toolID,
			Description:   ts.Name,
			Reversibility: "",
			BlastRadius:   "",
			Params: func() []policy.ParamDecl {
				out := make([]policy.ParamDecl, 0, len(ts.Parameters))
				for name, pd := range ts.Parameters {
					out = append(out, policy.ParamDecl{Name: name, Type: pd.Type, Required: pd.Required})
				}
				return out
			}(),
		})
	}
	if len(doc.PostRules) > 0 {
		scanner, err := postcondition.NewScanner(doc.PostRules, doc.MaxOutputBytes)
		if err == nil {
			art.postScanner = scanner
		}
	}
	return art
}

func currentEngine(a *policy.AtomicEngine) *policy.Engine {
	if a == nil {
		return nil
	}
	return a.Get()
}

func (p *Pipeline) currentArtifacts() *policyArtifacts {
	if v := p.artifacts.Load(); v != nil {
		if art, ok := v.(*policyArtifacts); ok && art != nil {
			return art
		}
	}
	return buildPolicyArtifacts(currentEngine(p.engine))
}

// ApplyPolicyBundle atomically applies a new policy generation bundle.
// The bundle includes rule evaluation engine + pre/post scanner artifacts.
func (p *Pipeline) ApplyPolicyBundle(doc *policy.Doc, newEngine *policy.Engine) error {
	if p.engine == nil {
		return fmt.Errorf("pipeline engine is nil")
	}
	if newEngine == nil {
		return fmt.Errorf("new policy engine is nil")
	}
	if doc == nil {
		doc = newEngine.Doc()
	}
	art := buildPolicyArtifacts(newEngine)
	if doc != nil && len(doc.PostRules) > 0 && art.postScanner == nil {
		return fmt.Errorf("failed to compile post-condition scanner")
	}
	p.engine.Swap(newEngine)
	p.artifacts.Store(art)
	p.syncRoutingFromPolicy(doc)
	return nil
}

func routingManifestFromDoc(doc *policy.Doc) (multiagent.RoutingManifest, bool) {
	if doc == nil || doc.OrchestratorManifest == nil || doc.OrchestratorManifest.AgentID == "" {
		return multiagent.RoutingManifest{}, false
	}
	om := doc.OrchestratorManifest
	m := multiagent.RoutingManifest{
		OrchestratorID:   om.AgentID,
		UndeclaredPolicy: om.UndeclaredInvocationPolicy,
	}
	if m.UndeclaredPolicy == "" {
		m.UndeclaredPolicy = "deny"
	}
	for _, inv := range om.PermittedInvocations {
		m.Entries = append(m.Entries, multiagent.RoutingEntry{
			AgentID:                  inv.AgentID,
			MaxInvocationsPerSession: inv.MaxInvocationsPerSession,
			RequiresPriorApproval:    inv.RequiresPriorApproval,
		})
	}
	return m, true
}

func (p *Pipeline) syncRoutingFromPolicy(doc *policy.Doc) {
	if p.routingGovernor == nil || doc == nil {
		return
	}
	if m, ok := routingManifestFromDoc(doc); ok {
		p.routingGovernor.ReplaceManifests([]multiagent.RoutingManifest{m})
	} else {
		p.routingGovernor.ReplaceManifests(nil)
	}
}

// Evaluate runs the 11-step evaluation pipeline and returns a Decision.
// The WAL record is written and fsynced before this function returns.
func (p *Pipeline) Evaluate(req CanonicalActionRequest) Decision {
	start := time.Now()
	art := p.currentArtifacts()
	engine := art.engine
	if engine == nil {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.PolicyLoadError,
			Reason:     "policy engine not loaded",
		}, p.sessions.Get(req.AgentID), start, nil)
	}
	doc := engine.Doc()

	if req.Timestamp.IsZero() {
		req.Timestamp = start
	}
	if req.InterceptAdapter == "" {
		req.InterceptAdapter = "sdk"
	}
	if req.CallID != "" {
		if !p.enterCallChain(req.CallID) {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.GovernanceDoubleWrapDenied,
				Reason:     "nested governance wrapping denied for active call chain",
			}, p.sessions.Get(req.AgentID), start, nil)
		}
		defer p.leaveCallChain(req.CallID)
	}

	// [0] Fail-closed on null-byte payloads to block string-termination bypasses.
	if containsNullByteString(req.ToolID) || containsNullByteValue(req.Args) {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.ScannerDeny,
			Reason:     "scanner detected null byte in tool request payload",
		}, p.sessions.Get(req.AgentID), start, nil)
	}

	// [0.1] Canonicalize args (CAR v1.0): NFKC normalization, confusable mapping,
	// null stripping, float 6-significant-figure rounding, string trimming.
	req.Args = canonicalize.Args(req.Args)

	// [0.2] Canonicalize tool ID: apply the same NFKC + confusable mapping
	// to prevent Unicode spoofing attacks on tool identifiers.
	req.ToolID = canonicalize.ToolID(req.ToolID)

	// [0.2] Workload identity fallback — if principal is missing or unverified,
	// try to inject an auto-detected workload identity.
	if (req.Principal == nil || !req.Principal.Verified) && p.workloadIdentity != nil {
		detectCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if detected, err := p.workloadIdentity.Identity(detectCtx); err == nil && detected != nil && detected.ID != "" {
			// Runtime trust path: when workload identity resolution succeeds, ensure
			// principal verification fields are populated for policy conditions.
			if !detected.Verified {
				detected.Verified = true
			}
			req.Principal = detected
		}
		cancel()
	}

	// [0.25] Principal verification source gate — accept verified=true only
	// when the verification method is from an authoritative workload source.
	if req.Principal != nil && req.Principal.Verified {
		if !principal.IsTrustedVerificationMethod(req.Principal.Method) {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.PrincipalVerificationUntrusted,
				Reason:     fmt.Sprintf("principal %q has untrusted or missing verification method", req.Principal.ID),
			}, p.sessions.Get(req.AgentID), start, nil)
		}
	}

	// [0.3] Principal revocation gate — revoked principals are hard denied.
	if req.Principal != nil && req.Principal.ID != "" && p.revocations != nil && p.revocations.IsRevoked(req.Principal.ID) {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.PrincipalRevoked,
			Reason:     fmt.Sprintf("principal %q is revoked", req.Principal.ID),
		}, p.sessions.Get(req.AgentID), start, nil)
	}

	// [0.4] Principal elevation overlay — apply active grant tier before eval.
	if req.Principal != nil && req.Principal.ID != "" && p.elevations != nil {
		if grant := p.elevations.ActiveGrant(req.Principal.ID); grant != nil && grant.ElevatedTier != "" {
			req.Principal.Tier = grant.ElevatedTier
		}
	}

	// [0.45] Strict runtime model identity verification.
	modelVerification := p.assessModelVerification(req, doc)
	if modelVerification != nil {
		req.ModelVerification = modelVerification
		if p.strictModelVerify && modelVerification.Required && !modelVerification.Verified {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.IdentityUnverified,
				Reason:     modelVerification.Reason,
			}, p.sessions.Get(req.AgentID), start, nil)
		}
	}

	// [1] Kill switch check — nanoseconds, no network.
	sess := p.sessions.Get(req.AgentID)
	resumeApprovalEnvelopeJSON := ""
	if p.sessionGovernor != nil {
		p.sessionGovernor.RegisterAgentNamespace(req.AgentID)
	}
	argProvenance, argProvErr := p.inferArgProvenance(req.AgentID, req.SessionID, req.Args)
	if argProvErr != nil {
		return p.decide(req, Decision{
			Effect:        EffectDeny,
			ReasonCode:    reasons.TelemetryHookError,
			Reason:        fmt.Sprintf("arg provenance inference failed: %v", argProvErr),
			PolicyVersion: engine.Version(),
		}, sess, start, nil)
	}
	if sess.IsKilled() {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.KillSwitchActive,
			Reason:     "agent kill switch is active",
		}, sess, start, argProvenance)
	}
	if p.bootstrap != nil {
		allowed, reason := p.bootstrap.CheckBootstrap(req.AgentID, req.ToolID)
		if !allowed {
			return p.decide(req, Decision{
				Effect:        EffectDeny,
				ReasonCode:    reasons.GovernanceBootstrapRequired,
				Reason:        reason,
				PolicyVersion: engine.Version(),
			}, sess, start, argProvenance)
		}
	}
	if strings.HasSuffix(req.CallID, "-resume") {
		envelopeJSON, code, reason := p.validateResumeApproval(req, sess, engine.Version())
		if code != "" {
			return p.decide(req, Decision{
				Effect:        EffectDeny,
				ReasonCode:    code,
				Reason:        reason,
				PolicyVersion: engine.Version(),
			}, sess, start, argProvenance)
		}
		resumeApprovalEnvelopeJSON = envelopeJSON
	}
	if p.runtimeMode == RuntimeModeAudit {
		return p.decide(req, Decision{
			Effect:               EffectPermit,
			ReasonCode:           reasons.UnknownReasonCode,
			Reason:               "audit mode passthrough; policy evaluation skipped",
			PolicyVersion:        engine.Version(),
			ApprovalEnvelopeJSON: resumeApprovalEnvelopeJSON,
			RetryPermitted:       true,
		}, sess, start, argProvenance)
	}
	parallelBudgetManager := p.ensureParallelBudgetManager(doc, req.SessionID, req.AgentID)
	if parallelBudgetManager != nil && parallelBudgetAgentCancelled(parallelBudgetManager, req.AgentID) {
		return p.decide(req, Decision{
			Effect:        EffectDeny,
			ReasonCode:    reasons.AggregateBudgetExceeded,
			Reason:        "parallel budget cancelled this agent after aggregate exceedance",
			PolicyVersion: engine.Version(),
		}, sess, start, argProvenance)
	}

	// [2] Phase check — tool visibility.
	if len(doc.Phases) > 0 {
		phaseName := sess.CurrentPhase()
		if phaseName == "" {
			phaseName = firstPhaseName(doc.Phases)
			sess.EnsurePhase(phaseName)
		}
		if transition, matched, err := engine.EvaluatePhaseTransition(phaseName, buildPhaseTransitionEvalContext(req, doc, sess)); err != nil {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.PolicyLoadError,
				Reason:     fmt.Sprintf("phase transition evaluation failed: %v", err),
			}, sess, start, argProvenance)
		} else if matched {
			switch transition.Effect {
			case "defer":
				reason := transition.Reason
				if reason == "" {
					reason = fmt.Sprintf("phase transition %q -> %q requires approval", transition.From, transition.To)
				}
				return p.decide(req, Decision{
					Effect:     EffectDefer,
					ReasonCode: reasons.PhaseTransitionDefer,
					Reason:     reason,
				}, sess, start, argProvenance)
			case "permit_transition":
				nextPhase := strings.TrimSpace(transition.To)
				if nextPhase == "" {
					return p.decide(req, Decision{
						Effect:     EffectDeny,
						ReasonCode: reasons.PolicyLoadError,
						Reason:     "phase transition target is empty",
					}, sess, start, argProvenance)
				}
				if _, ok := doc.Phases[nextPhase]; !ok {
					return p.decide(req, Decision{
						Effect:     EffectDeny,
						ReasonCode: reasons.PolicyLoadError,
						Reason:     fmt.Sprintf("phase transition target %q is not declared", nextPhase),
					}, sess, start, argProvenance)
				}
				if p.phaseManager != nil && nextPhase != phaseName {
					if p.phaseManager.CurrentPhase(req.AgentID) == "" {
						_ = p.phaseManager.SetPhase(req.AgentID, phaseName)
					}
					if _, err := p.phaseManager.Transition(req.AgentID, nextPhase, transition.Reason); err != nil {
						return p.decide(req, Decision{
							Effect:     EffectDeny,
							ReasonCode: reasons.PriorPhaseIncomplete,
							Reason:     fmt.Sprintf("phase transition %q -> %q rejected: %v", phaseName, nextPhase, err),
						}, sess, start, argProvenance)
					}
				}
				sess.SetPhase(nextPhase)
				phaseName = nextPhase
			}
		}
		if ph, ok := doc.Phases[phaseName]; ok && len(ph.Tools) > 0 {
			phaseTools, stepToolAllowlist := splitPhaseAndStepToolVisibility(ph.Tools)
			if !p.isToolAllowedInPhase(req.AgentID, phaseName, req.ToolID, phaseTools) {
				effect := EffectDeny
				reasonCode := reasons.OutOfPhaseToolCall
				if doc.PhaseEnforcement != nil {
					if strings.EqualFold(strings.TrimSpace(doc.PhaseEnforcement.OnOutOfPhaseCall), "defer") {
						effect = EffectDefer
					}
					if rc := strings.TrimSpace(doc.PhaseEnforcement.ReasonCode); rc != "" {
						reasonCode = rc
					}
				}
				return p.decide(req, Decision{
					Effect:     effect,
					ReasonCode: reasonCode,
					Reason:     fmt.Sprintf("tool %q not allowed in phase %q", req.ToolID, phaseName),
				}, sess, start, argProvenance)
			}
			if req.WorkflowStep != "" && len(stepToolAllowlist) > 0 {
				stepPatterns, ok := stepToolAllowlist[req.WorkflowStep]
				if !ok {
					return p.decide(req, Decision{
						Effect:     EffectDeny,
						ReasonCode: reasons.UnknownWorkflowStep,
						Reason: fmt.Sprintf("workflow step %q is not configured in phase %q",
							req.WorkflowStep, phaseName),
					}, sess, start, argProvenance)
				}
				stepAllowed := false
				for _, pattern := range stepPatterns {
					if matchToolPattern(pattern, req.ToolID) {
						stepAllowed = true
						break
					}
				}
				if !stepAllowed {
					return p.decide(req, Decision{
						Effect:     EffectDeny,
						ReasonCode: reasons.OutOfWorkflowStepToolCall,
						Reason: fmt.Sprintf("tool %q not allowed in workflow step %q (phase %q)",
							req.ToolID, req.WorkflowStep, phaseName),
					}, sess, start, argProvenance)
				}
			}
		}
	}

	// [2.5] Execution isolation check — enforce sandbox requirements.
	if doc.ExecutionIsolation != nil && doc.ExecutionIsolation.Enabled {
		required := requiredIsolationForTool(doc.ExecutionIsolation, req.ToolID)
		if required != sandbox.EnvNone {
			current := currentExecutionEnvironment(req)
			if current == sandbox.EnvNone {
				return p.decide(req, Decision{
					Effect:     EffectDeny,
					ReasonCode: reasons.IsolationRequired,
					Reason:     fmt.Sprintf("tool %q requires %s isolation", req.ToolID, required),
				}, sess, start, argProvenance)
			}
			if !meetsIsolationRequirement(current, required) {
				return p.decide(req, Decision{
					Effect:     EffectDeny,
					ReasonCode: reasons.IsolationRequired,
					Reason:     fmt.Sprintf("tool %q requires %s isolation (current: %s)", req.ToolID, required, current),
				}, sess, start, argProvenance)
			}
		}
	}

	// [2.6] Tool execution timeout contract — enforce canonical timeout semantics.
	if denied, code, reason, normalized := enforceExecutionTimeoutContract(req.ExecutionTimeoutMS, req.Args, doc, req.ToolID); denied {
		observe.EmitGovernanceLog(p.log, zapcore.WarnLevel, "execution timeout denied", observe.EventExecutionTimeoutDeny,
			zap.String("agent_id", req.AgentID),
			zap.String("session_id", req.SessionID),
			zap.String("call_id", req.CallID),
			zap.String("tool_id", req.ToolID),
			zap.String("reason_code", code),
			zap.String("reason", reason),
			zap.Int("requested_execution_timeout_ms", req.ExecutionTimeoutMS),
		)
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: code,
			Reason:     reason,
		}, sess, start, argProvenance)
	} else if normalized > 0 {
		req.ExecutionTimeoutMS = normalized
	}

	// [3] Pre-execution scanners (parallel, ~0.1ms total).
	if art.toolSchemas != nil {
		if errs := art.toolSchemas.ValidateArgs(req.ToolID, req.Args); len(errs) > 0 {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.SchemaValidationFail,
				Reason:     strings.Join(errs, "; "),
			}, sess, start, argProvenance)
		}
	}
	if denied, code, reason := runScanners(req); denied {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: code,
			Reason:     reason,
		}, sess, start, argProvenance)
	}

	// [3.1] Delegation scope check — ensure delegated calls are within scope.
	if req.Delegation != nil && req.Delegation.Len() > 0 {
		if !req.Delegation.ToolInScope(req.ToolID) {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.DelegationExceedsAuthority,
				Reason:     fmt.Sprintf("tool %q not in delegation scope", req.ToolID),
			}, sess, start, argProvenance)
		}
	}
	if req.Invocation != nil && req.Invocation.ID != "" && p.subPolicies != nil {
		if !p.subPolicies.IsToolAllowed(req.Invocation.ID, req.ToolID, true) {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.RoutingInvocationSubPolicyDenied,
				Reason:     fmt.Sprintf("tool %q denied by invocation sub-policy", req.ToolID),
			}, sess, start, argProvenance)
		}
	}

	// [3.10] Delegate constraints — enforce delegate scope/ttl on invoke_agent requests.
	if topologyInvokeTool(req.ToolID) && len(doc.DelegationPolicies) > 0 {
		target := extractTargetAgentID(req.Args)
		if target == "" {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.SchemaValidationFail,
				Reason:     "invoke_agent requires target_agent_id (or agent_id) in args",
			}, sess, start, argProvenance)
		}
		if allowed, code, reason := enforceDelegationConstraints(doc, target, req.Args); !allowed {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
		}
	}

	// [3.11] Orchestrator topology — invoke_agent targets must match orchestrator_manifest.
	if p.routingGovernor != nil && topologyInvokeTool(req.ToolID) && p.routingGovernor.HasManifest(req.AgentID) {
		target := extractTargetAgentID(req.Args)
		if target == "" {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.SchemaValidationFail,
				Reason:     "invoke_agent requires target_agent_id (or agent_id) in args",
			}, sess, start, argProvenance)
		}
		allowed, needApproval, routeReason := p.routingGovernor.CheckInvocation(req.AgentID, target, req.SessionID)
		if !allowed {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.RoutingManifestViolation,
				Reason:     routeReason,
			}, sess, start, argProvenance)
		}
		if needApproval {
			if resumeApprovalEnvelopeJSON != "" {
				goto routingApproved
			}
			token := routingDeferToken(req.CallID, req.ToolID, target)
			if _, err := p.defers.DeferWithToken(token, req.AgentID, req.ToolID, routeReason); err != nil {
				// duplicate token: keep same token semantics as policy defer
			}
			p.storeDeferContext(token, req, sess, engine.Version())
			return p.decide(req, Decision{
				Effect:        EffectDefer,
				ReasonCode:    reasons.RoutingUndeclaredInvocation,
				Reason:        routeReason,
				DeferToken:    token,
				PolicyVersion: engine.Version(),
			}, sess, start, argProvenance)
		}
	}
routingApproved:

	// [3.15] Session state write governor — enforce namespace + content safety.
	if strings.HasPrefix(req.ToolID, "session/write") && p.sessionGovernor != nil {
		key, _ := req.Args["key"].(string)
		if key == "" {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.SessionStateWriteBlocked,
				Reason:     "session state write requires string argument 'key'",
			}, sess, start, argProvenance)
		}
		value, _ := req.Args["value"]
		if allowed, code, reason := p.sessionGovernor.CanWrite(req.AgentID, key, value); !allowed {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
		}
		if _, _, targetsIntentWrite, err := parseIntentClassWrite(req.AgentID, req.Args); targetsIntentWrite && err != nil {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.SessionStateWriteBlocked,
				Reason:     err.Error(),
			}, sess, start, argProvenance)
		}
	}

	// [3.16] Loop governor — deny burst loops/repetitive invocation patterns.
	if p.loopGovernor != nil {
		if allowed, code, reason := p.loopGovernor.CheckAndTrack(req.AgentID, req.SessionID, req.ToolID, req.Args, req.Timestamp); !allowed {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
		}
	}

	// [3.2] Context guard check — verify external context freshness.
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
			}, sess, start, argProvenance)
		}
	}

	// [3.3] Cross-session accumulation guard — enforce principal-scoped limits across sessions.
	if len(doc.CrossSessionGuards) > 0 && p.crossSession != nil {
		allowed, effect, code, reason := p.crossSession.CheckAndTrack(doc.CrossSessionGuards, req, req.Timestamp)
		if !allowed {
			return p.decide(req, Decision{
				Effect:     effect,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
		}
	}

	// [4] Session state — increment call count.
	callCount := sess.IncrCallCount()

	// [4.5] Tool metadata lookup — needed by both budget reservation and policy conditions.
	toolMeta, toolCostUSD := lookupToolMeta(doc, req.ToolID)
	reservedCostUSD := 0.0
	reservedTokens := int64(0)
	finalizeDecision := func(dec Decision) Decision {
		dec.ReservedCostUSD = reservedCostUSD
		dec.ReservedTokens = reservedTokens
		return p.decide(req, dec, sess, start, argProvenance)
	}

	// [5] Budget enforcement — reserve projected cost before policy evaluation so
	// concurrent callers cannot race past session/daily cost limits.
	if doc.Budget != nil {
		if toolCostUSD > 0 && (doc.Budget.SessionUSD > 0 || doc.Budget.DailyUSD > 0) {
			ok, err := sess.CheckAndReserveCost(toolCostUSD, doc.Budget.SessionUSD, doc.Budget.DailyUSD)
			if err != nil {
				return finalizeDecision(Decision{
					Effect:         EffectDeny,
					ReasonCode:     reasons.SessionStateUnavailable,
					Reason:         "session cost reservation unavailable",
					RetryPermitted: true,
				})
			}
			if !ok {
				effect := EffectDeny
				if strings.EqualFold(strings.TrimSpace(doc.Budget.OnExceed), "defer") {
					effect = EffectDefer
				}
				code, reason := reservationExceededReason(sess, doc.Budget, toolCostUSD)
				return finalizeDecision(Decision{
					Effect:     effect,
					ReasonCode: code,
					Reason:     reason,
				})
			}
			reservedCostUSD = toolCostUSD
		}

		incomingTok := UsageTokensFromArgs(req.Args)
		if incomingTok > 0 && (doc.Budget.SessionTokens > 0 || doc.Budget.DailyTokens > 0) {
			ok, err := sess.CheckAndReserveTokens(incomingTok, doc.Budget.SessionTokens, doc.Budget.DailyTokens)
			if err != nil {
				return finalizeDecision(Decision{
					Effect:         EffectDeny,
					ReasonCode:     reasons.SessionStateUnavailable,
					Reason:         "session token reservation unavailable",
					RetryPermitted: true,
				})
			}
			if !ok {
				effect := EffectDeny
				if strings.EqualFold(strings.TrimSpace(doc.Budget.OnExceed), "defer") {
					effect = EffectDefer
				}
				code, reason := tokenReservationExceededReason(sess, doc.Budget, incomingTok)
				return finalizeDecision(Decision{
					Effect:     effect,
					ReasonCode: code,
					Reason:     reason,
				})
			}
			reservedTokens = incomingTok
		}

		if denied, code, reason := p.checkBudget(req.AgentID, doc.Budget, callCount, reservedCostUSD); denied {
			effect := EffectDeny
			if strings.EqualFold(strings.TrimSpace(doc.Budget.OnExceed), "defer") {
				effect = EffectDefer
			}
			return finalizeDecision(Decision{
				Effect:     effect,
				ReasonCode: code,
				Reason:     reason,
			})
		}
	}

	// [6] History ring buffer read — build history context for conditions.
	history := sess.History()

	// [7.5] Aggregation governor — cap cumulative risky actions per window.
	if p.aggGovernor != nil {
		if allowed, code, reason := p.aggGovernor.CheckAndTrack(req.SessionID, riskWeight(req.ToolID, toolMeta), req.Timestamp); !allowed {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
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
		Args:   req.Args,
		Vars:   runtimeenv.MergeDocVars(doc.Vars, runtimeenv.PolicyVarOverlay()),
		ToolID: req.ToolID,
		Session: policy.SessionCtx{
			CallCount:     callCount,
			History:       historyEntries,
			CostUSD:       subtractReservedCost(sess.CurrentCostUSD(), reservedCostUSD),
			DailyCostUSD:  subtractReservedCost(sess.DailyCostUSD(), reservedCostUSD),
			TokensSession: subtractReservedTokens(sess.CurrentSessionTokens(), reservedTokens),
			TokensDaily:   subtractReservedTokens(sess.DailyTokens(), reservedTokens),
			IntentClass:   sess.IntentClass(req.Timestamp),
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
			Depth:                 req.Delegation.Depth(),
			OriginAgent:           req.Delegation.OriginAgent(),
			OriginOrg:             req.Delegation.OriginOrg(),
			AgentIdentityVerified: req.Delegation.AllIdentitiesVerified(),
		}
	}

	evalCtx, evalCancel := context.WithTimeout(context.Background(), policyEvalAggregateTimeout)
	result := engine.EvaluateWithTimeout(evalCtx, req.ToolID, ctx)
	evalCancel()

	var d Decision
	switch strings.ToLower(result.Effect) {
	case "permit", "allow":
		d = Decision{
			Effect:        EffectPermit,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
			PolicyVersion: engine.Version(),
		}
	case "deny", "halt":
		// Generate an opaque denial token — keyed to call context, not to the
		// rule that matched, so agents cannot reverse-engineer policy structure.
		denialTok := "dnl_" + fmt.Sprintf("%x", sha256.Sum256([]byte(req.CallID+req.ToolID+req.AgentID+result.RuleID)))[:16]
		d = Decision{
			Effect:         EffectDeny,
			RuleID:         result.RuleID,
			ReasonCode:     result.ReasonCode,
			Reason:         result.Reason,
			DenialToken:    denialTok,
			RetryPermitted: false,
			PolicyVersion:  engine.Version(),
		}
	case "defer", "abstain", "pending":
		if resumeApprovalEnvelopeJSON != "" {
			d = Decision{
				Effect:        EffectPermit,
				RuleID:        result.RuleID,
				ReasonCode:    reasons.ApprovalGranted,
				Reason:        "action approved and resumed successfully",
				PolicyVersion: engine.Version(),
			}
			break
		}
		// Standing approval: policy-engine DEFER with a concrete rule may be
		// satisfied by an operator-registered time/scope bounded grant.
		if strings.TrimSpace(result.RuleID) != "" && p.standing != nil {
			if g := p.standing.TryConsume(req.AgentID, req.SessionID, req.ToolID, engine.Version(), result.RuleID, time.Now().UTC()); g != nil {
				d = Decision{
					Effect:     EffectPermit,
					RuleID:     result.RuleID,
					ReasonCode: reasons.StandingApprovalConsumed,
					Reason: fmt.Sprintf("standing grant %s consumed (issued_by=%s pattern=%q uses=%d max_uses=%d)",
						g.ID, g.IssuedBy, g.ToolPattern, g.Uses, g.MaxUses),
					PolicyVersion: engine.Version(),
				}
				break
			}
		}
		reason := result.Reason
		if reason == "" {
			reason = "action requires human approval"
		}
		// Generate deterministic token from call ID — single Defer() call (no double-registration).
		token := deterministicDeferToken(req.CallID, req.ToolID)
		// Register with the DEFER workflow exactly once.
		handle, err := p.defers.DeferWithTokenOpts(token, req.AgentID, req.ToolID, reason, deferwork.DeferOptions{
			ApprovalsRequired: result.ApprovalsRequired,
		})
		if err != nil || handle == nil {
			// If a handle with this token already exists (duplicate call), reuse the token.
			_ = handle
		}
		p.storeDeferContext(token, req, sess, engine.Version())
		d = Decision{
			Effect:        EffectDefer,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        reason,
			DeferToken:    token,
			PolicyVersion: engine.Version(),
		}
	case "shadow":
		d = Decision{
			Effect:        EffectShadow,
			RuleID:        result.RuleID,
			ReasonCode:    result.ReasonCode,
			Reason:        result.Reason,
			PolicyVersion: engine.Version(),
		}
	default:
		d = Decision{
			Effect:        EffectDeny,
			ReasonCode:    reasons.UnknownEffect,
			Reason:        "policy returned unknown effect: " + result.Effect,
			PolicyVersion: engine.Version(),
		}
	}

	if cat, sev := incidentFromMatchedRule(engine.Doc(), result.RuleID); cat != "" || sev != "" {
		d.IncidentCategory = cat
		d.IncidentSeverity = sev
	}
	if resumeApprovalEnvelopeJSON != "" {
		d.ApprovalEnvelopeJSON = resumeApprovalEnvelopeJSON
	}

	// [8.5] Credential broker injection for PERMIT path.
	// Conservative convention (when policy schema has no explicit broker block):
	// - enable when tool tag "credential:broker" exists OR args["_credential_broker"] is true
	// - require fail-closed when tag "credential:required" exists OR args["_credential_required"] is true
	// - scope from tag prefix "credential:scope:" OR args["_credential_scope"] (string)
	// - injected deterministic key path: args._faramesh.credential.value
	if d.Effect == EffectPermit {
		useBroker, required, scope := credentialBrokerPlan(toolMeta, req.Args)
		if useBroker {
			if p.credentialRouter == nil {
				if required {
					return p.decide(req, Decision{
						Effect:        EffectDeny,
						ReasonCode:    reasons.ContextMissing,
						Reason:        "credential broker required but not configured",
						PolicyVersion: engine.Version(),
					}, sess, start, argProvenance)
				}
			} else {
				handle, err := p.credentialRouter.BrokerCall(context.Background(), credential.FetchRequest{
					ToolID:    req.ToolID,
					Operation: credentialOperation(req.Args),
					Scope:     scope,
					AgentID:   req.AgentID,
				})
				if err != nil {
					if required {
						return p.decide(req, Decision{
							Effect:        EffectDeny,
							ReasonCode:    reasons.PolicyLoadError,
							Reason:        "credential broker required but fetch failed",
							PolicyVersion: engine.Version(),
						}, sess, start, argProvenance)
					}
				} else if handle != nil && handle.Credential != nil {
					injectBrokerCredential(req.Args, handle.Credential)
					_ = handle.Release(context.Background())
				}
			}
		}
	}

	return finalizeDecision(d)
}

func (p *Pipeline) isToolAllowedInPhase(agentID, phaseName, toolID string, fallbackTools []string) bool {
	if p.phaseManager != nil {
		if p.phaseManager.CurrentPhase(agentID) == "" {
			_ = p.phaseManager.SetPhase(agentID, phaseName)
		}
		if allowed, _ := p.phaseManager.IsToolAllowedInPhase(agentID, toolID); allowed {
			return true
		}
		return false
	}
	for _, pattern := range fallbackTools {
		if matchToolPattern(pattern, toolID) {
			return true
		}
	}
	return false
}

func (p *Pipeline) enterCallChain(callID string) bool {
	p.callChainMu.Lock()
	defer p.callChainMu.Unlock()
	if _, exists := p.activeCallChains[callID]; exists {
		return false
	}
	p.activeCallChains[callID] = struct{}{}
	return true
}

func (p *Pipeline) leaveCallChain(callID string) {
	p.callChainMu.Lock()
	delete(p.activeCallChains, callID)
	p.callChainMu.Unlock()
}

// checkBudget returns (true, code, reason) if the budget is exceeded.
func (p *Pipeline) checkBudget(agentID string, budget *policy.Budget, callCount int64, reservedCostUSD float64) (bool, string, string) {
	if budget.MaxCalls > 0 && callCount > budget.MaxCalls {
		return true, reasons.SessionToolLimit,
			fmt.Sprintf("session call limit reached (%d/%d)", callCount, budget.MaxCalls)
	}
	// Cost-based limits use the session cost tracked in session.State.
	sess := p.sessions.Get(agentID)
	if budget.SessionUSD > 0 {
		cost := subtractReservedCost(sess.CurrentCostUSD(), reservedCostUSD)
		if cost >= budget.SessionUSD {
			return true, reasons.BudgetSessionExceeded,
				fmt.Sprintf("session cost limit reached ($%.4f/$%.4f)", cost, budget.SessionUSD)
		}
	}
	if budget.DailyUSD > 0 {
		cost := subtractReservedCost(sess.DailyCostUSD(), reservedCostUSD)
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
func (p *Pipeline) decide(req CanonicalActionRequest, d Decision, sess *session.State, start time.Time, argProvenance map[string]string) Decision {
	_, decisionSpan := observe.StartOTLPSpan(context.Background(), "faramesh.govern.decision")
	defer observe.EndOTLPSpan(decisionSpan, nil)

	d = p.applyRuntimeMode(d)
	d.Latency = time.Since(start)
	d.AgentID = req.AgentID
	d.ToolID = req.ToolID
	d.SessionID = req.SessionID
	d.Timestamp = req.Timestamp
	d.ReasonCode = reasons.Normalize(d.ReasonCode)
	plannedRecordID := ""

	// Strict lifecycle hooks close callback/telemetry fail-open gaps for all
	// governance outcomes so observability and callback pipelines are never
	// silently bypassed.
	if shouldEnforceLifecycleHooks(d.Effect) {
		plannedRecordID = uuid.New().String()
		if code, err := p.enforceLifecycleHooks(req, d, plannedRecordID); err != nil {
			d = Decision{
				Effect:           EffectDeny,
				ReasonCode:       code,
				Reason:           fmt.Sprintf("governance lifecycle hook failure: %v", err),
				RetryPermitted:   true,
				PolicyVersion:    d.PolicyVersion,
				IncidentCategory: "governance_observability",
				IncidentSeverity: "high",
			}
			plannedRecordID = ""
		}
	}
	d.Latency = time.Since(start)

	// Record metrics.
	observe.Default.RecordDecision(string(d.Effect), d.ReasonCode, d.Latency)
	observe.RecordDecisionOTLP(context.Background(), string(d.Effect), d.ReasonCode, d.Latency)
	if d.Effect == EffectDeny && d.IncidentCategory != "" {
		sev := d.IncidentSeverity
		if sev == "" {
			sev = "unspecified"
		}
		observe.Default.RecordIncidentPrevented(d.IncidentCategory, sev)
	}
	if d.Effect == EffectShadow || d.Effect == EffectShadowPermit {
		observe.Default.RecordShadowExposure()
	}

	// [9] WAL write — fsync before returning.
	rec := p.buildRecordWithID(req, d, argProvenance, plannedRecordID)
	d.DPRRecordID = rec.RecordID
	if err := p.wal.Write(rec); err != nil {
		observe.Default.RecordWALWrite(false)
		if d.ReservedCostUSD > 0 {
			_ = sess.RollbackReservedCost(d.ReservedCostUSD)
		}
		if d.ReservedTokens > 0 {
			_ = sess.RollbackReservedTokens(d.ReservedTokens)
		}
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

	if p.routingGovernor != nil && d.Effect == EffectPermit && topologyInvokeTool(req.ToolID) && p.routingGovernor.HasManifest(req.AgentID) {
		if target := extractTargetAgentID(req.Args); target != "" {
			p.routingGovernor.RecordInvocation(req.AgentID, target, req.SessionID)
		}
	}

	// [10] Async: replicate to SQLite, update session history, sync to Horizon.
	// For PERMIT decisions: record cost against the session and daily accumulators
	// using the tool's declared cost_usd from the policy. This closes the gap
	// where sess.AddCost was never called, making USD budget enforcement inert.
	if p.store != nil {
		if p.dprQueue != nil {
			if err := p.dprQueue.EnqueueDPR(rec); err != nil {
				go func() {
					_ = p.store.Save(rec)
				}()
			}
		} else {
			go func() {
				_ = p.store.Save(rec)
			}()
		}
	}
	// History must be updated synchronously so sequence/deny-escalation
	// controls (e.g. deny_count_within) observe the latest decision
	// deterministically on the very next Evaluate() call.
	sess.RecordHistory(req.ToolID, string(d.Effect))
	if p.bootstrap != nil {
		p.bootstrap.MarkGoverned(req.AgentID)
	}
	if d.ReservedCostUSD > 0 {
		switch d.Effect {
		case EffectPermit, EffectShadow, EffectShadowPermit:
			_ = sess.ConfirmReservedCost(d.ReservedCostUSD)
		case EffectDeny:
			_ = sess.RollbackReservedCost(d.ReservedCostUSD)
		}
	}
	if d.ReservedTokens > 0 {
		switch d.Effect {
		case EffectPermit, EffectShadow, EffectShadowPermit:
			_ = sess.ConfirmReservedTokens(d.ReservedTokens)
		case EffectDeny:
			_ = sess.RollbackReservedTokens(d.ReservedTokens)
		}
	}
	if d.Effect == EffectPermit {
		if intentClass, ttl, targetsIntentWrite, err := parseIntentClassWrite(req.AgentID, req.Args); targetsIntentWrite && err == nil {
			sess.SetIntentClass(intentClass, ttl)
		}
	}
	if (d.Effect == EffectPermit || d.Effect == EffectShadow) && d.ReservedCostUSD == 0 {
		go p.accountCost(req.AgentID, req.ToolID, sess)
	}
	if d.Effect == EffectPermit || d.Effect == EffectShadow || d.Effect == EffectShadowPermit {
		if art := p.currentArtifacts(); art.engine != nil {
			if doc := art.engine.Doc(); doc != nil {
				if manager := p.ensureParallelBudgetManager(doc, req.SessionID, req.AgentID); manager != nil {
					if _, toolCostUSD := lookupToolMeta(doc, req.ToolID); toolCostUSD > 0 {
						_, _ = manager.RecordCost(req.AgentID, toolCostUSD)
					}
				}
			}
		}
	}
	if p.syncer != nil {
		go p.syncer.Send(d)
	}
	if p.toolInventory != nil {
		go func() {
			_ = p.toolInventory.RecordObservation(toolinventory.Observation{
				ToolID:           req.ToolID,
				Effect:           string(d.Effect),
				InterceptAdapter: req.InterceptAdapter,
				PolicyRuleID:     d.RuleID,
				CoverageTier:     coverageTierFromDecision(req, d),
				Timestamp:        req.Timestamp,
			})
		}()
	}
	if p.webhooks != nil {
		go p.emitWebhook(req, d)
	}
	if p.intentClassifier != nil && shouldRunIntentClassifier(req, d) {
		asyncReq := cloneCanonicalActionRequest(req)
		go p.runAsyncIntentClassifier(asyncReq, d)
	}

	// [11] Return Decision.
	return d
}

// accountCost looks up the declared cost_usd for the tool and records it.
// Called asynchronously after a PERMIT so it does not add latency.
func (p *Pipeline) accountCost(agentID, toolID string, sess *session.State) {
	art := p.currentArtifacts()
	if art.engine == nil {
		return
	}
	doc := art.engine.Doc()
	if doc.Tools == nil {
		return
	}
	t, ok := doc.Tools[toolID]
	if !ok || t.CostUSD <= 0 {
		return
	}
	sess.AddCost(t.CostUSD)
}

func lookupToolMeta(doc *policy.Doc, toolID string) (policy.ToolCtx, float64) {
	toolMeta := policy.ToolCtx{}
	if doc == nil || doc.Tools == nil {
		return toolMeta, 0
	}
	if t, ok := doc.Tools[toolID]; ok {
		toolMeta = policy.ToolCtx{
			Reversibility: t.Reversibility,
			BlastRadius:   t.BlastRadius,
			Tags:          t.Tags,
		}
		return toolMeta, t.CostUSD
	}
	return toolMeta, 0
}

func subtractReservedCost(total, reserved float64) float64 {
	if reserved <= 0 {
		return total
	}
	if total <= reserved {
		return 0
	}
	return total - reserved
}

func subtractReservedTokens(total, reserved int64) int64 {
	if reserved <= 0 {
		return total
	}
	if total <= reserved {
		return 0
	}
	return total - reserved
}

func tokenReservationExceededReason(sess *session.State, budget *policy.Budget, incoming int64) (string, string) {
	if sess == nil || budget == nil {
		return reasons.BudgetSessionTokensExceeded, "token budget exceeded"
	}
	curS := sess.CurrentSessionTokens()
	curD := sess.DailyTokens()
	if budget.SessionTokens > 0 && curS+incoming > budget.SessionTokens {
		return reasons.BudgetSessionTokensExceeded,
			fmt.Sprintf("session token limit exceeded (%d + %d > %d)", curS, incoming, budget.SessionTokens)
	}
	if budget.DailyTokens > 0 && curD+incoming > budget.DailyTokens {
		return reasons.BudgetDailyTokensExceeded,
			fmt.Sprintf("daily token limit exceeded (%d + %d > %d)", curD, incoming, budget.DailyTokens)
	}
	return reasons.BudgetSessionTokensExceeded, "token budget exceeded"
}

func reservationExceededReason(sess *session.State, budget *policy.Budget, costUSD float64) (string, string) {
	if sess == nil || budget == nil {
		return reasons.BudgetSessionExceeded, "session cost reservation rejected"
	}
	if budget.SessionUSD > 0 && sess.CurrentCostUSD()+costUSD > budget.SessionUSD {
		return reasons.BudgetSessionExceeded,
			fmt.Sprintf("session cost limit would be exceeded by reserved cost ($%.4f + $%.4f > $%.4f)", sess.CurrentCostUSD(), costUSD, budget.SessionUSD)
	}
	if budget.DailyUSD > 0 && sess.DailyCostUSD()+costUSD > budget.DailyUSD {
		return reasons.BudgetDailyExceeded,
			fmt.Sprintf("daily cost limit would be exceeded by reserved cost ($%.4f + $%.4f > $%.4f)", sess.DailyCostUSD(), costUSD, budget.DailyUSD)
	}
	return reasons.BudgetSessionExceeded, "session cost reservation rejected"
}

// buildRecord constructs the DPR record for this decision.
func (p *Pipeline) buildRecord(req CanonicalActionRequest, d Decision, argProvenance map[string]string) *dpr.Record {
	return p.buildRecordWithID(req, d, argProvenance, "")
}

// buildRecordWithID constructs the DPR record and uses recordID when provided.
func (p *Pipeline) buildRecordWithID(req CanonicalActionRequest, d Decision, argProvenance map[string]string, recordID string) *dpr.Record {
	p.chainLock.Lock()
	prevHash := p.chainMu[req.AgentID]
	if prevHash == "" {
		// Genesis record: deterministic chain-start marker per agent.
		prevHash = dpr.GenesisPrevHash(req.AgentID)
	}
	if strings.TrimSpace(recordID) == "" {
		recordID = uuid.New().String()
	}

	rec := &dpr.Record{
		SchemaVersion:      dpr.SchemaVersion,
		CARVersion:         CARVersion,
		RecordID:           recordID,
		PrevRecordHash:     prevHash,
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ToolID:             req.ToolID,
		InterceptAdapter:   req.InterceptAdapter,
		ExecutionTimeoutMS: req.ExecutionTimeoutMS,
		Effect:             string(d.Effect),
		MatchedRuleID:      d.RuleID,
		ReasonCode:         d.ReasonCode,
		Reason:             d.Reason,
		DenialToken:        d.DenialToken,
		IncidentCategory:   d.IncidentCategory,
		IncidentSeverity:   d.IncidentSeverity,
		PolicyVersion:      d.PolicyVersion,
		PolicySourceType:   p.policySourceType,
		PolicySourceID:     p.policySourceID,
		ArgsStructuralSig:  dpr.ArgsSignature(req.Args),
		ArgProvenance:      argProvenance,
		SelectorSnapshot:   selectorSnapshotForRecord(req.Args),
		ApprovalEnvelope:   d.ApprovalEnvelopeJSON,
		CreatedAt:          req.Timestamp.UTC(),
	}
	if p.degraded != nil {
		rec.DegradedMode = p.degraded.Current().String()
	}
	setRecordCredentialMeta(rec, credentialMetaFromArgs(req.Args))
	setRecordNetworkEvidence(rec, req.Args, d)
	setRecordModelVerificationMeta(rec, req.ModelVerification)

	// Populate principal hash if available.
	if req.Principal != nil && req.Principal.ID != "" {
		rec.PrincipalIDHash = fmt.Sprintf("%x",
			sha256.Sum256([]byte(req.Principal.ID)))[:16]
	}

	// Store FPL version from current policy.
	art := p.currentArtifacts()
	if art.engine != nil {
		if doc := art.engine.Doc(); doc != nil {
			rec.FPLVersion = doc.FarameshVersion
		}
	}

	rec.ComputeHash()
	// Prefer asymmetric Ed25519 signing when available; fall back to HMAC.
	if len(p.signingPrivKey) > 0 && len(p.signingPubKey) > 0 {
		// Attempt Ed25519 signing. Use dpr.SignWithEd25519 which handles
		// base64 encoding of signature and public key fields.
		if err := rec.SignWithEd25519(ed25519.PrivateKey(p.signingPrivKey), ed25519.PublicKey(p.signingPubKey)); err != nil {
			// If signing fails, fall back to HMAC if configured.
			p.log.Warn("ed25519 signing failed; falling back to HMAC if available", zap.Error(err))
			if len(p.hmacKey) > 0 {
				m := hmac.New(sha256.New, p.hmacKey)
				_, _ = m.Write([]byte(rec.RecordID + rec.RecordHash))
				rec.HMACSig = fmt.Sprintf("%x", m.Sum(nil))
			}
		}
	} else if len(p.hmacKey) > 0 {
		m := hmac.New(sha256.New, p.hmacKey)
		_, _ = m.Write([]byte(rec.RecordID + rec.RecordHash))
		rec.HMACSig = fmt.Sprintf("%x", m.Sum(nil))
	}
	p.chainMu[req.AgentID] = rec.RecordHash
	p.chainLock.Unlock()
	return rec
}

func enforceExecutionTimeoutContract(reqTimeoutMS int, args map[string]any, doc *policy.Doc, toolID string) (bool, string, string, int) {
	normalized := reqTimeoutMS
	if normalized <= 0 {
		normalized = timeoutFromArgs(args)
	}
	if normalized > 0 && (normalized < minExecutionTimeoutMS || normalized > maxExecutionTimeoutMS) {
		return true, reasons.ExecutionTimeoutInvalid,
			fmt.Sprintf("execution timeout %dms out of bounds [%dms,%dms]", normalized, minExecutionTimeoutMS, maxExecutionTimeoutMS), 0
	}

	required := false
	minMS := minExecutionTimeoutMS
	maxMS := maxExecutionTimeoutMS
	if doc != nil && doc.Tools != nil {
		if t, ok := doc.Tools[toolID]; ok {
			for _, raw := range t.Tags {
				tag := strings.ToLower(strings.TrimSpace(raw))
				switch {
				case tag == "timeout:required":
					required = true
				case strings.HasPrefix(tag, "timeout:min_ms:"):
					if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(tag, "timeout:min_ms:"))); err == nil && v > 0 {
						minMS = v
					}
				case strings.HasPrefix(tag, "timeout:max_ms:"):
					if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(tag, "timeout:max_ms:"))); err == nil && v > 0 {
						maxMS = v
					}
				}
			}
		}
	}
	if minMS < minExecutionTimeoutMS {
		minMS = minExecutionTimeoutMS
	}
	if maxMS > maxExecutionTimeoutMS {
		maxMS = maxExecutionTimeoutMS
	}
	if minMS > maxMS {
		minMS, maxMS = maxMS, minMS
	}
	if required && normalized <= 0 {
		return true, reasons.ExecutionTimeoutRequired, "tool policy requires execution timeout", 0
	}
	if normalized > 0 && (normalized < minMS || normalized > maxMS) {
		return true, reasons.ExecutionTimeoutPolicyViolation,
			fmt.Sprintf("execution timeout %dms violates policy bounds [%dms,%dms]", normalized, minMS, maxMS), 0
	}
	return false, "", "", normalized
}

func buildPhaseTransitionEvalContext(req CanonicalActionRequest, doc *policy.Doc, sess *session.State) policy.EvalContext {
	history := sess.History()
	historyEntries := make([]map[string]any, len(history))
	for i, h := range history {
		historyEntries[i] = map[string]any{
			"tool":      h.ToolID,
			"effect":    h.Effect,
			"timestamp": h.Timestamp.Unix(),
		}
	}

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

	ctx := policy.EvalContext{
		Args:   req.Args,
		Vars:   runtimeenv.MergeDocVars(doc.Vars, runtimeenv.PolicyVarOverlay()),
		ToolID: req.ToolID,
		Session: policy.SessionCtx{
			CallCount:     sess.CallCount(),
			History:       historyEntries,
			CostUSD:       sess.CurrentCostUSD(),
			DailyCostUSD:  sess.DailyCostUSD(),
			TokensSession: sess.CurrentSessionTokens(),
			TokensDaily:   sess.DailyTokens(),
		},
		Tool: toolMeta,
	}

	if req.Principal != nil {
		ctx.Principal = &policy.PrincipalCtx{
			ID:       req.Principal.ID,
			Tier:     req.Principal.Tier,
			Role:     req.Principal.Role,
			Org:      req.Principal.Org,
			Verified: req.Principal.Verified,
		}
	}
	if req.Delegation != nil {
		ctx.Delegation = &policy.DelegationCtx{
			Depth:                 req.Delegation.Depth(),
			OriginAgent:           req.Delegation.OriginAgent(),
			OriginOrg:             req.Delegation.OriginOrg(),
			AgentIdentityVerified: req.Delegation.AllIdentitiesVerified(),
		}
	}

	return ctx
}
func timeoutFromArgs(args map[string]any) int {
	if len(args) == 0 {
		return 0
	}
	if v, ok := toPositiveIntMS(args["execution_timeout_ms"]); ok {
		return v
	}
	if v, ok := toPositiveIntMS(args["timeout_ms"]); ok {
		return v
	}
	if sec, ok := toPositiveIntMS(args["execution_timeout_secs"]); ok {
		return sec * 1000
	}
	if sec, ok := toPositiveIntMS(args["timeout_secs"]); ok {
		return sec * 1000
	}
	return 0
}

func toPositiveIntMS(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		if n > 0 {
			return n, true
		}
	case int64:
		if n > 0 && n <= int64(^uint(0)>>1) {
			return int(n), true
		}
	case float64:
		if n > 0 {
			return int(n), true
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil && i > 0 {
			return i, true
		}
	}
	return 0, false
}

func credentialBrokerPlan(toolMeta policy.ToolCtx, args map[string]any) (use bool, required bool, scope string) {
	for _, tag := range toolMeta.Tags {
		t := strings.ToLower(strings.TrimSpace(tag))
		if t == "credential:broker" {
			use = true
		}
		if t == "credential:required" {
			use = true
			required = true
		}
		if strings.HasPrefix(t, "credential:scope:") {
			use = true
			scope = strings.TrimPrefix(t, "credential:scope:")
		}
	}
	if v, ok := args["_credential_broker"].(bool); ok && v {
		use = true
	}
	if v, ok := args["_credential_required"].(bool); ok && v {
		use = true
		required = true
	}
	if scope == "" {
		if s, ok := args["_credential_scope"].(string); ok {
			scope = strings.TrimSpace(s)
		}
	}
	return use, required, scope
}

func credentialOperation(args map[string]any) string {
	if s, ok := args["_credential_operation"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return "invoke"
}

func injectBrokerCredential(args map[string]any, cred *credential.Credential) {
	if args == nil || cred == nil {
		return
	}
	root, _ := args["_faramesh"].(map[string]any)
	if root == nil {
		root = map[string]any{}
		args["_faramesh"] = root
	}
	root["credential"] = map[string]any{
		"value":    cred.Value,
		"source":   cred.Source,
		"scope":    cred.Scope,
		"brokered": true,
	}
}

func credentialMetaFromArgs(args map[string]any) credential.DPRMeta {
	if args == nil {
		return credential.DPRMeta{}
	}
	root, _ := args["_faramesh"].(map[string]any)
	if root == nil {
		return credential.DPRMeta{}
	}
	cm, _ := root["credential"].(map[string]any)
	if cm == nil {
		return credential.DPRMeta{}
	}
	meta := credential.DPRMeta{}
	if b, ok := cm["brokered"].(bool); ok {
		meta.Brokered = b
	}
	if s, ok := cm["source"].(string); ok {
		meta.Source = s
	}
	if s, ok := cm["scope"].(string); ok {
		meta.Scope = s
	}
	return meta
}

func setRecordCredentialMeta(rec *dpr.Record, meta credential.DPRMeta) {
	if rec == nil {
		return
	}
	rv := reflect.ValueOf(rec)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return
	}
	if f := elem.FieldByName("CredentialBrokered"); f.IsValid() && f.CanSet() && f.Kind() == reflect.Bool {
		f.SetBool(meta.Brokered)
	}
	if f := elem.FieldByName("CredentialSource"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
		f.SetString(meta.Source)
	}
	if f := elem.FieldByName("CredentialScope"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
		f.SetString(meta.Scope)
	}
}

func setRecordNetworkEvidence(rec *dpr.Record, args map[string]any, decision Decision) {
	if rec == nil {
		return
	}
	if args != nil {
		if mode := networkEvidenceString(args["hardening_mode"]); mode != "" {
			rec.HardeningMode = strings.ToLower(mode)
		}
		if host := networkEvidenceString(args["host"]); host != "" {
			rec.NetworkHostHash = networkEvidenceHash(strings.ToLower(host))
		}
		if port := networkEvidencePort(args["port"]); port > 0 {
			rec.NetworkPort = port
		}
		if resolved := networkEvidenceString(args["resolved_ip"]); resolved != "" {
			rec.NetworkResolvedIPHash = networkEvidenceHash(strings.ToLower(resolved))
		}
		if rewritten, ok := args["inference_model_rewrite_applied"].(bool); ok {
			rec.InferenceModelRewriteApplied = rewritten
		}
	}
	if decision.Effect == EffectPermit && strings.EqualFold(strings.TrimSpace(decision.ReasonCode), reasons.NetworkL7AuditViolation) {
		rec.NetworkAuditBypass = true
	}
}

func networkEvidenceHash(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)[:16]
}

func networkEvidenceString(v any) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func networkEvidencePort(v any) int {
	switch typed := v.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float32:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

// AcquireCredentialHandle retrieves an ephemeral credential handle via the configured
// credential router. When required is false, missing router or fetch failures are
// tolerated and return a nil handle.
func (p *Pipeline) AcquireCredentialHandle(ctx context.Context, req credential.FetchRequest, required bool) (*credential.CredentialHandle, error) {
	if p == nil {
		if required {
			return nil, fmt.Errorf("pipeline is nil")
		}
		return nil, nil
	}
	if p.credentialRouter == nil {
		if required {
			return nil, fmt.Errorf("credential router not configured")
		}
		return nil, nil
	}
	if strings.TrimSpace(req.Operation) == "" {
		req.Operation = "invoke"
	}
	handle, err := p.credentialRouter.BrokerCall(ctx, req)
	if err != nil {
		if required {
			return nil, err
		}
		return nil, nil
	}
	return handle, nil
}

func (p *Pipeline) assessModelVerification(req CanonicalActionRequest, doc *policy.Doc) *ModelVerificationResult {
	declared := declaredModelIdentityFromPolicy(doc)
	presented := presentedModelIdentityFromRequest(req)

	if declared == nil && presented == nil && !p.strictModelVerify {
		return nil
	}

	registered := p.ListModelIdentities()
	result := &ModelVerificationResult{
		Strict:          p.strictModelVerify,
		Required:        p.strictModelVerify && declared != nil,
		Declared:        declared,
		Presented:       presented,
		RegisteredCount: len(registered),
	}

	if declared == nil {
		result.Verified = true
		result.Reason = "policy does not declare model identity requirements"
		return result
	}

	if len(registered) == 0 {
		result.Verified = false
		result.Reason = "no model identities are registered in daemon core"
		return result
	}

	if presented == nil {
		result.Verified = false
		result.Reason = "runtime request did not include model identity"
		return result
	}

	match, reason := findRegisteredModelMatch(declared, presented, registered)
	if match == nil {
		result.Verified = false
		result.Reason = reason
		return result
	}

	result.Registered = &ModelIdentity{
		Name:        match.Name,
		Fingerprint: match.Fingerprint,
		Provider:    match.Provider,
		Version:     match.Version,
	}

	if strings.TrimSpace(match.Fingerprint) == "" {
		result.Verified = false
		result.Reason = fmt.Sprintf("registered model %q has no fingerprint", match.Name)
		return result
	}
	if strings.TrimSpace(presented.Fingerprint) == "" {
		result.Verified = false
		result.Reason = "runtime model fingerprint is required"
		return result
	}

	if err := verifyModelIdentityAgainstRegistration(declared, *match); err != nil {
		result.Verified = false
		result.Reason = err.Error()
		return result
	}
	if err := verifyModelIdentityAgainstRegistration(presented, *match); err != nil {
		result.Verified = false
		result.Reason = err.Error()
		return result
	}

	result.Verified = true
	result.Reason = "runtime model identity verified against registry policy"
	return result
}

func findRegisteredModelMatch(declared, presented *ModelIdentity, registered []ModelRegistration) (*ModelRegistration, string) {
	if declared != nil && strings.TrimSpace(declared.Name) != "" {
		for i := range registered {
			if strings.EqualFold(registered[i].Name, declared.Name) {
				return &registered[i], ""
			}
		}
		return nil, fmt.Sprintf("declared model %q is not registered", declared.Name)
	}

	if presented != nil && strings.TrimSpace(presented.Name) != "" {
		for i := range registered {
			if strings.EqualFold(registered[i].Name, presented.Name) {
				return &registered[i], ""
			}
		}
	}

	for i := range registered {
		if identityMatchesRegistration(declared, registered[i]) && identityMatchesRegistration(presented, registered[i]) {
			return &registered[i], ""
		}
	}

	return nil, "no registered model matches declared/runtime identity"
}

func identityMatchesRegistration(identity *ModelIdentity, reg ModelRegistration) bool {
	if identity == nil {
		return true
	}
	if strings.TrimSpace(identity.Name) != "" && !strings.EqualFold(identity.Name, reg.Name) {
		return false
	}
	if strings.TrimSpace(identity.Fingerprint) != "" && !strings.EqualFold(identity.Fingerprint, reg.Fingerprint) {
		return false
	}
	if strings.TrimSpace(identity.Provider) != "" && !strings.EqualFold(identity.Provider, reg.Provider) {
		return false
	}
	if strings.TrimSpace(identity.Version) != "" && strings.TrimSpace(identity.Version) != strings.TrimSpace(reg.Version) {
		return false
	}
	return true
}

func verifyModelIdentityAgainstRegistration(identity *ModelIdentity, reg ModelRegistration) error {
	if identity == nil {
		return nil
	}
	if strings.TrimSpace(identity.Name) != "" && !strings.EqualFold(identity.Name, reg.Name) {
		return fmt.Errorf("model name mismatch: presented=%q registered=%q", identity.Name, reg.Name)
	}
	if strings.TrimSpace(identity.Fingerprint) != "" && !strings.EqualFold(identity.Fingerprint, reg.Fingerprint) {
		return fmt.Errorf("model fingerprint mismatch for %q", reg.Name)
	}
	if strings.TrimSpace(identity.Provider) != "" && strings.TrimSpace(reg.Provider) != "" && !strings.EqualFold(identity.Provider, reg.Provider) {
		return fmt.Errorf("model provider mismatch for %q", reg.Name)
	}
	if strings.TrimSpace(identity.Version) != "" && strings.TrimSpace(reg.Version) != "" && strings.TrimSpace(identity.Version) != strings.TrimSpace(reg.Version) {
		return fmt.Errorf("model version mismatch for %q", reg.Name)
	}
	return nil
}

func declaredModelIdentityFromPolicy(doc *policy.Doc) *ModelIdentity {
	if doc == nil || doc.Vars == nil {
		return nil
	}

	var m ModelIdentity
	if raw, ok := doc.Vars["model"]; ok {
		switch v := raw.(type) {
		case string:
			m.Name = v
		case map[string]any:
			m.Name = stringFromAny(v["name"])
			m.Fingerprint = stringFromAny(v["fingerprint"])
			m.Provider = stringFromAny(v["provider"])
			m.Version = stringFromAny(v["version"])
		}
	}
	if raw, ok := doc.Vars["model_identity"]; ok {
		if v, ok := raw.(map[string]any); ok {
			if strings.TrimSpace(m.Name) == "" {
				m.Name = stringFromAny(v["name"])
			}
			if strings.TrimSpace(m.Fingerprint) == "" {
				m.Fingerprint = stringFromAny(v["fingerprint"])
			}
			if strings.TrimSpace(m.Provider) == "" {
				m.Provider = stringFromAny(v["provider"])
			}
			if strings.TrimSpace(m.Version) == "" {
				m.Version = stringFromAny(v["version"])
			}
		}
	}
	if strings.TrimSpace(m.Name) == "" {
		m.Name = stringFromAny(doc.Vars["model_name"])
	}
	if strings.TrimSpace(m.Name) == "" {
		m.Name = stringFromAny(doc.Vars["agent.model"])
	}
	if strings.TrimSpace(m.Fingerprint) == "" {
		m.Fingerprint = stringFromAny(doc.Vars["model_fingerprint"])
	}
	if strings.TrimSpace(m.Provider) == "" {
		m.Provider = stringFromAny(doc.Vars["model_provider"])
	}
	if strings.TrimSpace(m.Version) == "" {
		m.Version = stringFromAny(doc.Vars["model_version"])
	}

	m.Name = strings.TrimSpace(m.Name)
	m.Fingerprint = strings.ToLower(strings.TrimSpace(m.Fingerprint))
	m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
	m.Version = strings.TrimSpace(m.Version)
	if m.Name == "" && m.Fingerprint == "" && m.Provider == "" && m.Version == "" {
		return nil
	}
	return &m
}

func presentedModelIdentityFromRequest(req CanonicalActionRequest) *ModelIdentity {
	if req.Model != nil {
		m := *req.Model
		m.Name = strings.TrimSpace(m.Name)
		m.Fingerprint = strings.ToLower(strings.TrimSpace(m.Fingerprint))
		m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
		m.Version = strings.TrimSpace(m.Version)
		if m.Name != "" || m.Fingerprint != "" || m.Provider != "" || m.Version != "" {
			return &m
		}
	}

	if req.Args == nil {
		return nil
	}

	m := &ModelIdentity{
		Name:        stringFromAny(req.Args["_model_name"]),
		Fingerprint: stringFromAny(req.Args["_model_fingerprint"]),
		Provider:    stringFromAny(req.Args["_model_provider"]),
		Version:     stringFromAny(req.Args["_model_version"]),
	}

	if fm, ok := req.Args["_faramesh"].(map[string]any); ok {
		if rawModel, ok := fm["model"].(map[string]any); ok {
			if strings.TrimSpace(m.Name) == "" {
				m.Name = stringFromAny(rawModel["name"])
			}
			if strings.TrimSpace(m.Fingerprint) == "" {
				m.Fingerprint = stringFromAny(rawModel["fingerprint"])
			}
			if strings.TrimSpace(m.Provider) == "" {
				m.Provider = stringFromAny(rawModel["provider"])
			}
			if strings.TrimSpace(m.Version) == "" {
				m.Version = stringFromAny(rawModel["version"])
			}
		}
	}

	m.Name = strings.TrimSpace(m.Name)
	m.Fingerprint = strings.ToLower(strings.TrimSpace(m.Fingerprint))
	m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
	m.Version = strings.TrimSpace(m.Version)
	if m.Name == "" && m.Fingerprint == "" && m.Provider == "" && m.Version == "" {
		return nil
	}
	return m
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func setRecordModelVerificationMeta(rec *dpr.Record, verification *ModelVerificationResult) {
	if rec == nil || verification == nil {
		return
	}

	evidence := map[string]any{
		"required":         verification.Required,
		"strict":           verification.Strict,
		"verified":         verification.Verified,
		"reason":           verification.Reason,
		"registered_count": verification.RegisteredCount,
	}
	if verification.Declared != nil {
		evidence["declared"] = modelIdentityToMap(verification.Declared)
	}
	if verification.Presented != nil {
		evidence["presented"] = modelIdentityToMap(verification.Presented)
	}
	if verification.Registered != nil {
		evidence["registered"] = modelIdentityToMap(verification.Registered)
	}

	if rec.OperatorResults == nil {
		rec.OperatorResults = map[string]any{}
	}
	const evidenceKey = "model_identity_verification"
	rec.OperatorResults[evidenceKey] = evidence

	for _, item := range rec.CustomOperatorsEvaluated {
		if item == evidenceKey {
			return
		}
	}
	rec.CustomOperatorsEvaluated = append(rec.CustomOperatorsEvaluated, evidenceKey)
}

func modelIdentityToMap(identity *ModelIdentity) map[string]any {
	if identity == nil {
		return nil
	}
	out := map[string]any{}
	if strings.TrimSpace(identity.Name) != "" {
		out["name"] = identity.Name
	}
	if strings.TrimSpace(identity.Fingerprint) != "" {
		out["fingerprint"] = identity.Fingerprint
	}
	if strings.TrimSpace(identity.Provider) != "" {
		out["provider"] = identity.Provider
	}
	if strings.TrimSpace(identity.Version) != "" {
		out["version"] = identity.Version
	}
	return out
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

// RegisterStandingGrant adds a standing approval grant.
func (p *Pipeline) RegisterStandingGrant(in standing.Input) (*standing.Grant, error) {
	if p == nil || p.standing == nil {
		return nil, fmt.Errorf("standing registry unavailable")
	}
	return p.standing.Add(in)
}

// RevokeStandingGrant removes a grant by id.
func (p *Pipeline) RevokeStandingGrant(id string) (bool, error) {
	if p == nil || p.standing == nil {
		return false, fmt.Errorf("standing registry unavailable")
	}
	return p.standing.Revoke(id)
}

// CloseStandingPersistence closes the standing registry SQLite handle when the
// pipeline was built with a file-backed registry.
func (p *Pipeline) CloseStandingPersistence() error {
	if p == nil || p.standing == nil {
		return nil
	}
	return p.standing.Close()
}

// ListStandingGrants returns a snapshot of active grants.
func (p *Pipeline) ListStandingGrants() []standing.Grant {
	if p == nil || p.standing == nil {
		return nil
	}
	return p.standing.List()
}

// SessionManager returns the session manager.
func (p *Pipeline) SessionManager() *session.Manager {
	return p.sessions
}

// SessionGovernor returns the session write governor.
func (p *Pipeline) SessionGovernor() *session.Governor {
	return p.sessionGovernor
}

// RegisterModelIdentity upserts a model identity entry in daemon-core state.
func (p *Pipeline) RegisterModelIdentity(name, fingerprint, provider, version string) ModelRegistration {
	now := time.Now().UTC().Format(time.RFC3339)
	rec := ModelRegistration{
		Name:        strings.TrimSpace(name),
		Fingerprint: strings.ToLower(strings.TrimSpace(fingerprint)),
		Provider:    strings.ToLower(strings.TrimSpace(provider)),
		Version:     strings.TrimSpace(version),
		UpdatedAt:   now,
	}

	p.modelMu.Lock()
	defer p.modelMu.Unlock()
	if existing, ok := p.models[rec.Name]; ok {
		rec.Registered = existing.Registered
	} else {
		rec.Registered = now
	}
	p.models[rec.Name] = rec
	return rec
}

// ListModelIdentities returns a deterministic snapshot of registered models.
func (p *Pipeline) ListModelIdentities() []ModelRegistration {
	p.modelMu.RLock()
	out := make([]ModelRegistration, 0, len(p.models))
	for _, rec := range p.models {
		out = append(out, rec)
	}
	p.modelMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// VerifyModelIdentity returns runtime model verification status for an agent.
func (p *Pipeline) VerifyModelIdentity(agentID string, presented *ModelIdentity) ModelVerificationResult {
	art := p.currentArtifacts()
	var doc *policy.Doc
	if art != nil && art.engine != nil {
		doc = art.engine.Doc()
	}
	registeredCount := len(p.ListModelIdentities())
	result := p.assessModelVerification(CanonicalActionRequest{
		AgentID: agentID,
		Model:   presented,
	}, doc)
	if result == nil {
		return ModelVerificationResult{Verified: true, Reason: "model verification not required", Strict: p.strictModelVerify, RegisteredCount: registeredCount}
	}
	return *result
}

// StatusSnapshot returns a runtime health snapshot for control-plane introspection.
func (p *Pipeline) StatusSnapshot() RuntimeStatus {
	art := p.currentArtifacts()
	policyVersion := ""
	if art != nil && art.engine != nil {
		policyVersion = strings.TrimSpace(art.engine.Version())
	}
	activeSessions := 0
	if p.sessions != nil {
		activeSessions = p.sessions.Count()
	}
	return RuntimeStatus{
		PolicyLoaded:   policyVersion != "",
		PolicyVersion:  policyVersion,
		DPRHealthy:     p.wal != nil,
		ActiveSessions: activeSessions,
		TrustLevel:     "unknown",
	}
}

// ToolMetadata returns policy-declared metadata for a tool ID.
// Exact tool IDs are preferred; wildcard tool patterns are used as fallback.
func (p *Pipeline) ToolMetadata(toolID string) ToolRuntimeMeta {
	meta := ToolRuntimeMeta{ToolID: toolID}
	art := p.currentArtifacts()
	if art == nil || art.engine == nil || art.engine.Doc() == nil || len(art.engine.Doc().Tools) == 0 {
		return meta
	}

	doc := art.engine.Doc()
	if t, ok := doc.Tools[toolID]; ok {
		meta.Reversibility = strings.TrimSpace(t.Reversibility)
		meta.BlastRadius = strings.TrimSpace(t.BlastRadius)
		meta.Tags = append([]string(nil), t.Tags...)
		return meta
	}

	bestPattern := ""
	for pattern := range doc.Tools {
		if !strings.Contains(pattern, "*") {
			continue
		}
		if !matchToolPattern(pattern, toolID) {
			continue
		}
		if len(pattern) > len(bestPattern) {
			bestPattern = pattern
		}
	}

	if bestPattern != "" {
		t := doc.Tools[bestPattern]
		meta.Reversibility = strings.TrimSpace(t.Reversibility)
		meta.BlastRadius = strings.TrimSpace(t.BlastRadius)
		meta.Tags = append([]string(nil), t.Tags...)
	}

	return meta
}

// CredentialBrokerDiagnostics returns policy+router visibility for brokered tool execution.
func (p *Pipeline) CredentialBrokerDiagnostics() CredentialBrokerDiagnostics {
	out := CredentialBrokerDiagnostics{
		RouterConfigured: p.credentialRouter != nil,
		Tools:            []CredentialBrokerToolDiagnostic{},
	}
	if p.credentialRouter != nil {
		out.Backends = p.credentialRouter.BackendNames()
		out.FallbackBackend = p.credentialRouter.FallbackBackendName()
		out.Routes = p.credentialRouter.RoutesSnapshot()
	}

	art := p.currentArtifacts()
	if art == nil || art.engine == nil || art.engine.Doc() == nil || len(art.engine.Doc().Tools) == 0 {
		return out
	}

	doc := art.engine.Doc()
	keys := make([]string, 0, len(doc.Tools))
	for toolID := range doc.Tools {
		keys = append(keys, toolID)
	}
	sort.Strings(keys)

	tools := make([]CredentialBrokerToolDiagnostic, 0, len(keys))
	for _, toolID := range keys {
		decl := doc.Tools[toolID]
		tags := append([]string(nil), decl.Tags...)
		useBroker, required, scope := credentialBrokerPlan(policy.ToolCtx{Tags: tags}, nil)
		entry := CredentialBrokerToolDiagnostic{
			ToolID:         toolID,
			Tags:           tags,
			BrokerEnabled:  useBroker,
			Required:       required,
			Scope:          scope,
			RouteAvailable: p.credentialRouter != nil,
		}
		if p.credentialRouter != nil {
			resolved := p.credentialRouter.ResolveRoute(toolID)
			entry.MatchedRoute = resolved.Pattern
			entry.Backend = resolved.Backend
			entry.UsesFallback = resolved.UsedFallback
		}
		if useBroker {
			out.BrokerEnabledCount++
		}
		if required {
			out.RequiredCount++
		}
		tools = append(tools, entry)
	}
	out.Tools = tools
	out.ToolCount = len(tools)

	return out
}

func (p *Pipeline) emitWebhook(req CanonicalActionRequest, d Decision) {
	var t webhook.EventType
	switch d.Effect {
	case EffectPermit, EffectShadow:
		t = webhook.EventPermit
	case EffectDeny:
		t = webhook.EventDeny
	case EffectDefer:
		t = webhook.EventDefer
	default:
		return
	}
	p.webhooks.Send(webhook.Event{
		Version:    webhook.EventSchemaVersionV1,
		Type:       t,
		Timestamp:  req.Timestamp.UTC().Format(time.RFC3339),
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		ToolID:     req.ToolID,
		Effect:     string(d.Effect),
		RuleID:     d.RuleID,
		ReasonCode: d.ReasonCode,
		Reason:     d.Reason,
		RecordID:   d.DPRRecordID,
		Token:      d.DeferToken,
	})
}

func (p *Pipeline) storeDeferContext(token string, req CanonicalActionRequest, sess *session.State, policyHash string) {
	if token == "" || p.defers == nil {
		return
	}
	ctx := deferwork.NewDeferContext(token, req.SessionID, policyHash, req.Args)
	ctx.SetSessionStateHash(deferSessionStateSnapshot(sess, req))
	p.defers.StoreContext(ctx)
}

func (p *Pipeline) validateResumeApproval(req CanonicalActionRequest, sess *session.State, policyHash string) (string, string, string) {
	if p.defers == nil {
		return "", reasons.ApprovalDenied, "resume approval validation unavailable"
	}
	var (
		ctx *deferwork.DeferContext
		env *deferwork.ApprovalEnvelope
	)
	for _, candidate := range resumeDeferTokens(req) {
		if candidate == "" {
			continue
		}
		candidateCtx := p.defers.Context(candidate)
		candidateEnv, ok := p.defers.ApprovalEnvelope(candidate)
		if candidateCtx == nil || !ok || candidateEnv == nil {
			continue
		}
		ctx = candidateCtx
		env = candidateEnv
		break
	}
	if ctx == nil {
		return "", reasons.ApprovalDenied, "resume approval context is missing"
	}
	if !env.Approved || env.Status != deferwork.StatusApproved {
		return "", reasons.ApprovalDenied, "approval envelope does not authorize execution"
	}
	if err := deferwork.VerifyApprovalEnvelope(p.hmacKey, env); err != nil {
		return "", reasons.ApprovalDenied, fmt.Sprintf("approval envelope verification failed: %v", err)
	}
	validation := ctx.ValidateForResume(policyHash, deferSessionStateHash(sess, req), deferwork.DefaultTimeout)
	if !validation.Valid {
		return "", reasons.ApprovalDenied, strings.Join(validation.Warnings, "; ")
	}
	currentArgsJSON := canonicalArgsJSON(req.Args)
	if currentArgsJSON != canonicalArgsJSON(ctx.ArgSnapshot) && currentArgsJSON != canonicalArgsJSON(env.ModifiedArgs) {
		return "", reasons.ApprovalDenied, "resume args do not match the approved defer context"
	}
	body, err := json.Marshal(env)
	if err != nil {
		return "", reasons.ApprovalDenied, fmt.Sprintf("serialize approval envelope: %v", err)
	}
	return string(body), "", ""
}

func deterministicDeferToken(callID, toolID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(callID+toolID)))[:8]
}

// DeterministicDeferToken returns the DEFER token derived from a stable call ID
// and tool ID. Exposed for MCP and other adapters that must align with pipeline
// defer token semantics.
func DeterministicDeferToken(callID, toolID string) string {
	return deterministicDeferToken(callID, toolID)
}

func routingDeferToken(callID, toolID, target string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(callID+toolID+target)))[:8]
}

func resumeDeferTokens(req CanonicalActionRequest) []string {
	originalCallID := strings.TrimSuffix(req.CallID, "-resume")
	tokens := []string{deterministicDeferToken(originalCallID, req.ToolID)}
	if topologyInvokeTool(req.ToolID) {
		if target := extractTargetAgentID(req.Args); target != "" {
			routeToken := routingDeferToken(originalCallID, req.ToolID, target)
			if routeToken != tokens[0] {
				tokens = append(tokens, routeToken)
			}
		}
	}
	return tokens
}

func deferSessionStateHash(sess *session.State, req CanonicalActionRequest) string {
	ctx := deferwork.NewDeferContext("", req.SessionID, "", nil)
	ctx.SetSessionStateHash(deferSessionStateSnapshot(sess, req))
	return ctx.SessionStateHash
}

func deferSessionStateSnapshot(sess *session.State, req CanonicalActionRequest) map[string]any {
	if sess == nil {
		return map[string]any{
			"session_id": req.SessionID,
			"tool_id":    req.ToolID,
		}
	}
	return map[string]any{
		"session_id":       req.SessionID,
		"tool_id":          req.ToolID,
		"phase":            sess.CurrentPhase(),
		"session_cost_usd": fmt.Sprintf("%.6f", sess.CurrentCostUSD()),
		"daily_cost_usd":   fmt.Sprintf("%.6f", sess.DailyCostUSD()),
	}
}

func (p *Pipeline) ensureParallelBudgetManager(doc *policy.Doc, sessionID, agentID string) *multiagent.BudgetManager {
	if doc == nil || doc.ParallelBudget == nil || sessionID == "" || agentID == "" {
		return nil
	}
	cfg := doc.ParallelBudget
	if len(cfg.Agents) > 0 && !containsString(cfg.Agents, agentID) {
		return nil
	}
	p.budgetMu.Lock()
	defer p.budgetMu.Unlock()
	manager := p.budgetManagers[sessionID]
	if manager == nil {
		manager = multiagent.NewBudgetManager(sessionID, cfg.AggregateMaxCostUSD)
		p.budgetManagers[sessionID] = manager
	}
	_ = manager.AllocateAgent(agentID, cfg.PerAgentMaxCostUSD)
	return manager
}

func parallelBudgetAgentCancelled(manager *multiagent.BudgetManager, agentID string) bool {
	if manager == nil {
		return false
	}
	status := manager.Status()
	for _, agent := range status.Agents {
		if agent.AgentID == agentID {
			return agent.Cancelled
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
}

func canonicalArgsJSON(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	body, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(body)
}

func coverageTierFromDecision(req CanonicalActionRequest, d Decision) string {
	switch {
	case req.InterceptAdapter == "sdk" && d.RuleID != "":
		return "A"
	case req.InterceptAdapter == "mcp" && d.RuleID != "":
		return "B"
	case req.InterceptAdapter == "proxy" || req.InterceptAdapter == "daemon":
		return "C"
	case d.RuleID != "":
		return "D"
	default:
		return "E"
	}
}

// ScanOutput runs post-execution output scanning on a tool's output.
// Adapters call this after a PERMIT'd tool completes, before returning
// the output to the agent's context. Returns the scan result which may
// contain redacted output or a denial.
func (p *Pipeline) ScanOutput(toolID, output string) postcondition.ScanResult {
	_, postScanSpan := observe.StartOTLPSpan(context.Background(), "faramesh.postscan")
	defer observe.EndOTLPSpan(postScanSpan, nil)

	if err := p.recordToolOutputs("", "", toolID, "", map[string]any{"output": output}); err != nil {
		observe.RecordPostScanOTLP(context.Background(), "DENIED")
		return postcondition.ScanResult{
			Outcome:    postcondition.OutcomeDenied,
			Output:     "",
			ReasonCode: reasons.TelemetryHookError,
			Reason:     fmt.Sprintf("tool output telemetry recording failed: %v", err),
		}
	}
	scanner := p.currentArtifacts().postScanner
	if scanner == nil {
		observe.RecordPostScanOTLP(context.Background(), "PASS")
		return postcondition.ScanResult{Outcome: postcondition.OutcomePass, Output: output}
	}
	res := scanner.Scan(toolID, output)
	switch res.Outcome {
	case postcondition.OutcomeRedacted:
		observe.Default.RecordPostScan("REDACTED")
		observe.RecordPostScanOTLP(context.Background(), "REDACTED")
	case postcondition.OutcomeDenied:
		observe.Default.RecordPostScan("DENIED")
		observe.RecordPostScanOTLP(context.Background(), "DENIED")
	default:
		observe.Default.RecordPostScan("pass")
		observe.RecordPostScanOTLP(context.Background(), "PASS")
	}
	return res
}

func (p *Pipeline) enforceLifecycleHooks(req CanonicalActionRequest, d Decision, recordID string) (string, error) {
	if err := p.recordToolOutputs(req.AgentID, req.SessionID, req.ToolID, recordID, req.Args); err != nil {
		return reasons.TelemetryHookError, err
	}

	if d.Effect == EffectPermit || d.Effect == EffectShadow {
		principalID := ""
		if req.Principal != nil {
			principalID = req.Principal.ID
		}
		if err := observe.Default.RecordPermitAccess(observe.AccessEvent{
			AgentID:     req.AgentID,
			SessionID:   req.SessionID,
			ToolID:      req.ToolID,
			RuleID:      d.RuleID,
			Timestamp:   req.Timestamp,
			PrincipalID: principalID,
			DPRID:       recordID,
		}); err != nil {
			return reasons.TelemetryHookError, err
		}
	}

	if d.RuleID != "" {
		if err := observe.Default.ObserveRule(observe.RuleObservation{
			AgentID:   req.AgentID,
			SessionID: req.SessionID,
			ToolID:    req.ToolID,
			RuleID:    d.RuleID,
			Effect:    string(d.Effect),
			Timestamp: req.Timestamp,
		}); err != nil {
			return reasons.TelemetryHookError, err
		}
	}

	if p.callbacks != nil {
		if err := p.callbacks.FireOnDecision(callbacks.OnDecisionPayload{
			AgentID:    req.AgentID,
			SessionID:  req.SessionID,
			ToolID:     req.ToolID,
			Effect:     string(d.Effect),
			RuleID:     d.RuleID,
			ReasonCode: d.ReasonCode,
			RecordID:   recordID,
		}); err != nil {
			return reasons.CallbackError, err
		}
	}

	return "", nil
}

func shouldEnforceLifecycleHooks(effect Effect) bool {
	switch effect {
	case EffectPermit, EffectDeny, EffectDefer, EffectShadow, EffectShadowPermit:
		return true
	default:
		return false
	}
}

func (p *Pipeline) applyRuntimeMode(d Decision) Decision {
	switch p.runtimeMode {
	case RuntimeModeShadow:
		return overrideDecisionForShadow(d)
	case RuntimeModeAudit:
		return Decision{
			Effect:               EffectShadowPermit,
			RuleID:               d.RuleID,
			ReasonCode:           reasons.UnknownReasonCode,
			Reason:               "audit mode passthrough; policy evaluation skipped for enforcement",
			RetryPermitted:       true,
			DeferToken:           "",
			DenialToken:          "",
			ShadowActualOutcome:  d.Effect,
			PolicyVersion:        d.PolicyVersion,
			IncidentCategory:     d.IncidentCategory,
			IncidentSeverity:     d.IncidentSeverity,
			ReservedCostUSD:      d.ReservedCostUSD,
			ApprovalEnvelopeJSON: d.ApprovalEnvelopeJSON,
		}
	default:
		return d
	}
}

func overrideDecisionForShadow(d Decision) Decision {
	if d.Effect == EffectShadow || d.Effect == EffectShadowPermit {
		return d
	}
	out := d
	out.Effect = EffectShadowPermit
	out.ShadowActualOutcome = d.Effect
	out.DeferToken = ""
	out.DenialToken = ""
	switch d.Effect {
	case EffectDeny:
		out.ReasonCode = reasons.ShadowDeny
	case EffectDefer:
		out.ReasonCode = reasons.ShadowDefer
	}
	return out
}

func (p *Pipeline) inferArgProvenance(agentID, sessionID string, args map[string]any) (out map[string]string, err error) {
	if p.provenance == nil {
		return nil, nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("arg provenance tracker panic: %v", r)
		}
	}()
	out, err = p.provenance.InferArgProvenance(agentID, sessionID, args)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Pipeline) recordToolOutputs(agentID, sessionID, toolID, recordID string, args map[string]any) (err error) {
	if p.provenance == nil || len(args) == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tool output tracker panic: %v", r)
		}
	}()

	const maxOutputs = 6
	emitted := 0
	for _, key := range []string{"output", "result", "response", "body", "stdout", "stderr"} {
		v, ok := args[key]
		if !ok {
			continue
		}
		if err := p.provenance.RecordToolOutput(agentID, sessionID, toolID, recordID, v); err != nil {
			return fmt.Errorf("record tool output %q: %w", key, err)
		}
		emitted++
		if emitted >= maxOutputs {
			return nil
		}
	}

	return nil
}

// scanner patterns for pre-execution safety checks.
var (
	destructiveShellRe = regexp.MustCompile(`(?i)(rm\s+-[rf]+|mkfs|dd\s+if=|:\(\)\{|>\s*/dev/sd|shred\s+)`)
	secretPatternRe    = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|password\s*=\s*\S+|api[_-]?key\s*=\s*\S+)`)
	pathTraversalRe    = regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e|%252e%252e)`)
	sqlInjectionRe     = regexp.MustCompile(`(?i)(('|")\s*(;|--|\/\*|OR\s+1\s*=\s*1|DROP\s+TABLE|UNION\s+SELECT))`)
	codeExecRe         = regexp.MustCompile(`(?i)(\beval\s*\(|\bexec\s*\(|__import__\s*\(|\bsubprocess\b)`)
	sensitivePathRe    = regexp.MustCompile(`(?i)(\.env$|\.pem$|id_rsa|credentials|\.secret|config\.yaml$|\.key$|\.p12$|/etc/passwd|/etc/shadow)`)
	multimodalScanner  = postcondition.NewMultimodalScanner()
	allowedIntentClass = map[string]struct{}{
		"routine":                 {},
		"anomalous":               {},
		"potentially_adversarial": {},
		"high_risk_intent":        {},
	}
)

// runScanners runs the pre-execution safety scanners.
// Returns (true, reasonCode, reason) if the request should be denied.
func runScanners(req CanonicalActionRequest) (bool, string, string) {
	argsStr := fmt.Sprintf("%v", req.Args)

	if multimodalScanner != nil && len(req.Args) > 0 {
		for _, result := range multimodalScanner.ScanArgs(req.Args) {
			if result.Safe || len(result.Threats) == 0 {
				continue
			}
			threat := result.Threats[0]
			reason := fmt.Sprintf("scanner detected encoded %s pattern in argument %q", threat.Type, result.ArgPath)
			if enc := strings.TrimSpace(result.Encoding); enc != "" {
				reason = fmt.Sprintf("scanner detected encoded %s pattern in argument %q (%s)", threat.Type, result.ArgPath, enc)
			}
			return true, reasons.MultimodalInjection, reason
		}
	}

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

func selectorSnapshotForRecord(args map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	snapshot, ok := sanitizeSelectorValue(args).(map[string]any)
	if !ok || len(snapshot) == 0 {
		return nil
	}
	return snapshot
}

func sanitizeSelectorValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			if isSensitiveSelectorKey(key) {
				out[key] = "[redacted]"
				continue
			}
			out[key] = sanitizeSelectorValue(child)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, sanitizeSelectorValue(item))
		}
		return out
	case []string:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, sanitizeSelectorValue(item))
		}
		return out
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return x
		}
		// Redact obvious secret material in values, but keep path-like strings that
		// scanners match (e.g. /etc/passwd) so WAL replay can reproduce scanner DENY
		// parity without legacy reason passthrough.
		if secretPatternRe.MatchString(s) {
			return "[redacted]"
		}
		return x
	default:
		return v
	}
}

func isSensitiveSelectorKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "secret") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "api_key") ||
		strings.Contains(key, "apikey") ||
		strings.Contains(key, "client_secret") ||
		strings.Contains(key, "access_key") ||
		strings.Contains(key, "private_key") ||
		strings.Contains(key, "credential") ||
		key == "authorization"
}

func firstPhaseName(phases map[string]policy.Phase) string {
	if _, ok := phases["init"]; ok {
		return "init"
	}
	keys := make([]string, 0, len(phases))
	for k := range phases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func matchToolPattern(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(toolID, prefix)
	}
	return toolID == pattern
}

func splitPhaseAndStepToolVisibility(tools []string) ([]string, map[string][]string) {
	phaseTools := make([]string, 0, len(tools))
	stepTools := make(map[string][]string)
	for _, raw := range tools {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}
		step, toolPattern, ok := parseStepScopedToolPattern(pattern)
		if !ok {
			phaseTools = append(phaseTools, pattern)
			continue
		}
		stepTools[step] = append(stepTools[step], toolPattern)
	}
	return phaseTools, stepTools
}

func parseStepScopedToolPattern(pattern string) (step string, toolPattern string, ok bool) {
	const prefix = "step:"
	if !strings.HasPrefix(pattern, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(pattern, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	step = strings.TrimSpace(parts[0])
	toolPattern = strings.TrimSpace(parts[1])
	if step == "" || toolPattern == "" {
		return "", "", false
	}
	return step, toolPattern, true
}

func requiredIsolationForTool(cfg *policy.ExecutionIsolation, toolID string) sandbox.Environment {
	if cfg == nil {
		return sandbox.EnvNone
	}
	for pattern, mode := range cfg.ToolPolicy {
		matched, err := path.Match(pattern, toolID)
		if err != nil {
			matched = matchToolPattern(pattern, toolID)
		}
		if !matched {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "required":
			return mapBackendToEnvironment(cfg.DefaultBackend)
		case "optional", "none":
			return sandbox.EnvNone
		}
	}
	return sandbox.EnvNone
}

func mapBackendToEnvironment(backend string) sandbox.Environment {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "docker", "docker_sandbox":
		return sandbox.EnvDocker
	case "gvisor":
		return sandbox.EnvGVisor
	case "firecracker":
		return sandbox.EnvFirecracker
	case "wasm":
		return sandbox.EnvWASM
	default:
		return sandbox.EnvNone
	}
}

func currentExecutionEnvironment(req CanonicalActionRequest) sandbox.Environment {
	if req.ExecutionEnvironment != "" {
		return mapBackendToEnvironment(req.ExecutionEnvironment)
	}
	if raw, ok := req.Args["execution_environment"]; ok {
		if s, ok := raw.(string); ok {
			return mapBackendToEnvironment(s)
		}
	}
	if raw, ok := req.Args["sandbox_environment"]; ok {
		if s, ok := raw.(string); ok {
			return mapBackendToEnvironment(s)
		}
	}
	return sandbox.EnvNone
}

func meetsIsolationRequirement(current, required sandbox.Environment) bool {
	rank := func(env sandbox.Environment) int {
		switch env {
		case sandbox.EnvNone:
			return 0
		case sandbox.EnvDocker, sandbox.EnvWASM:
			return 1
		case sandbox.EnvGVisor:
			return 2
		case sandbox.EnvFirecracker:
			return 3
		default:
			return 0
		}
	}
	return rank(current) >= rank(required)
}

func containsNullByteString(s string) bool {
	return strings.IndexByte(s, 0) >= 0
}

func containsNullByteValue(v any) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case string:
		return containsNullByteString(val)
	case map[string]any:
		for k, child := range val {
			if containsNullByteString(k) || containsNullByteValue(child) {
				return true
			}
		}
		return false
	case []any:
		for _, child := range val {
			if containsNullByteValue(child) {
				return true
			}
		}
		return false
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return false
		}
		return containsNullByteValue(rv.Elem().Interface())
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			k := iter.Key()
			if k.Kind() == reflect.String && containsNullByteString(k.String()) {
				return true
			}
			if containsNullByteValue(iter.Value().Interface()) {
				return true
			}
		}
		return false
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if containsNullByteValue(rv.Index(i).Interface()) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func shouldRunIntentClassifier(req CanonicalActionRequest, d Decision) bool {
	if strings.TrimSpace(req.AgentID) == "" || strings.TrimSpace(req.SessionID) == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.ToolID)), "session/write") {
		return false
	}
	switch d.Effect {
	case EffectPermit, EffectShadow:
		return true
	default:
		return false
	}
}

func cloneCanonicalActionRequest(req CanonicalActionRequest) CanonicalActionRequest {
	copyReq := req
	copyReq.Args = cloneArgsMap(req.Args)
	return copyReq
}

func cloneArgsMap(args map[string]any) map[string]any {
	if len(args) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(args))
	for k, v := range args {
		cloned[k] = cloneArgValue(v)
	}
	return cloned
}

func cloneArgValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, child := range typed {
			out[k] = cloneArgValue(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = cloneArgValue(typed[i])
		}
		return out
	default:
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			return v
		}
		switch rv.Kind() {
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return v
			}
			out := make(map[string]any, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				out[iter.Key().String()] = cloneArgValue(iter.Value().Interface())
			}
			return out
		case reflect.Slice:
			if rv.IsNil() {
				return v
			}
			out := make([]any, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				out[i] = cloneArgValue(rv.Index(i).Interface())
			}
			return out
		default:
			return v
		}
	}
}

func (p *Pipeline) runAsyncIntentClassifier(req CanonicalActionRequest, d Decision) {
	if p.intentClassifier == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	classification, err := p.intentClassifier.Classify(ctx, req, d)
	if err != nil {
		p.log.Debug("intent classifier call failed",
			zap.String("agent_id", req.AgentID),
			zap.String("session_id", req.SessionID),
			zap.String("tool_id", req.ToolID),
			zap.Error(err),
		)
		return
	}

	intentClass := strings.TrimSpace(classification.Class)
	if intentClass == "" {
		return
	}

	args := map[string]any{
		"key":   req.AgentID + "/intent/class",
		"value": intentClass,
	}
	if classification.TTL > 0 {
		ttlSeconds := int(classification.TTL.Round(time.Second) / time.Second)
		if ttlSeconds > 0 {
			args["ttl_seconds"] = ttlSeconds
		}
	}

	writeReq := CanonicalActionRequest{
		CallID:           "intent-classifier-" + uuid.NewString(),
		AgentID:          req.AgentID,
		SessionID:        req.SessionID,
		ToolID:           "session/write",
		Args:             args,
		Timestamp:        time.Now().UTC(),
		InterceptAdapter: "intent_classifier",
	}
	writeDecision := p.Evaluate(writeReq)
	if writeDecision.Effect != EffectPermit {
		p.log.Debug("intent classifier session write not permitted",
			zap.String("agent_id", req.AgentID),
			zap.String("session_id", req.SessionID),
			zap.String("reason_code", writeDecision.ReasonCode),
			zap.String("reason", writeDecision.Reason),
		)
	}
}

func parseIntentClassWrite(agentID string, args map[string]any) (intentClass string, ttl time.Duration, targets bool, err error) {
	if len(args) == 0 {
		return "", 0, false, nil
	}
	rawKey, _ := args["key"].(string)
	normalizedKey := strings.ToLower(strings.TrimSpace(rawKey))
	if normalizedKey == "" {
		return "", 0, false, nil
	}
	if agent := strings.ToLower(strings.TrimSpace(agentID)); agent != "" {
		prefix := agent + "/"
		normalizedKey = strings.TrimPrefix(normalizedKey, prefix)
	}
	if normalizedKey != "intent/class" && normalizedKey != "intent_class" {
		return "", 0, false, nil
	}

	targets = true
	class := strings.ToLower(strings.TrimSpace(fmt.Sprint(args["value"])))
	class = strings.ReplaceAll(class, "-", "_")
	class = strings.ReplaceAll(class, " ", "_")
	if class == "" {
		return "", 0, true, fmt.Errorf("intent class write requires a non-empty value")
	}
	if _, ok := allowedIntentClass[class]; !ok {
		return "", 0, true, fmt.Errorf("unsupported intent class %q", class)
	}

	return class, parseIntentClassTTL(args), true, nil
}

func parseIntentClassTTL(args map[string]any) time.Duration {
	ttl := 10 * time.Minute
	if raw, ok := args["ttl"]; ok {
		switch v := raw.(type) {
		case string:
			if parsed, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && parsed > 0 {
				ttl = parsed
			}
		default:
			if seconds := parsePositiveInt(raw); seconds > 0 {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	for _, key := range []string{"ttl_seconds", "ttl_secs", "ttl_sec"} {
		if raw, ok := args[key]; ok {
			if seconds := parsePositiveInt(raw); seconds > 0 {
				ttl = time.Duration(seconds) * time.Second
				break
			}
		}
	}
	if ttl < 30*time.Second {
		return 30 * time.Second
	}
	if ttl > 24*time.Hour {
		return 24 * time.Hour
	}
	return ttl
}

func parsePositiveInt(v any) int {
	switch typed := v.(type) {
	case int:
		if typed > 0 {
			return typed
		}
	case int32:
		if typed > 0 {
			return int(typed)
		}
	case int64:
		if typed > 0 {
			return int(typed)
		}
	case float32:
		if typed > 0 {
			return int(typed)
		}
	case float64:
		if typed > 0 {
			return int(typed)
		}
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func riskWeight(toolID string, meta policy.ToolCtx) int {
	weight := 0
	switch strings.ToLower(strings.TrimSpace(meta.BlastRadius)) {
	case "scoped", "system", "external":
		weight++
	}
	if strings.EqualFold(meta.Reversibility, "irreversible") {
		weight++
	}
	if strings.HasPrefix(toolID, "danger/") {
		weight++
	}
	return weight
}

func incidentFromMatchedRule(doc *policy.Doc, ruleID string) (category, severity string) {
	if doc == nil || ruleID == "" {
		return "", ""
	}
	for _, r := range doc.Rules {
		if r.ID == ruleID {
			return r.IncidentCategory, r.IncidentSeverity
		}
	}
	return "", ""
}
