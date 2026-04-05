package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	provenance        observe.ArgProvenanceTracker
	phaseManager      *phases.PhaseManager
	policySourceType  string
	policySourceID    string
	strictModelVerify bool
	hmacKey           []byte
	log               *zap.Logger
	artifacts         atomic.Value // *policyArtifacts
	callChainMu       sync.Mutex
	activeCallChains  map[string]struct{}
	modelMu           sync.RWMutex
	models            map[string]ModelRegistration
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

const (
	minExecutionTimeoutMS = 50
	maxExecutionTimeoutMS = 60 * 60 * 1000
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
	Provenance              observe.ArgProvenanceTracker
	PhaseManager            *phases.PhaseManager
	PolicySourceType        string
	PolicySourceID          string
	StrictModelVerification bool
	HMACKey                 []byte
	Log                     *zap.Logger
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
		provenance:        cfg.Provenance,
		phaseManager:      cfg.PhaseManager,
		policySourceType:  cfg.PolicySourceType,
		policySourceID:    cfg.PolicySourceID,
		strictModelVerify: cfg.StrictModelVerification,
		hmacKey:           cfg.HMACKey,
		log:               cfg.Log,
		activeCallChains:  make(map[string]struct{}),
		models:            make(map[string]ModelRegistration),
	}
	if p.log == nil {
		p.log = zap.NewNop()
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

	// [0] Canonicalize args (CAR v1.0): NFKC normalization, confusable mapping,
	// null stripping, float 6-significant-figure rounding, string trimming.
	req.Args = canonicalize.Args(req.Args)

	// [0.1] Canonicalize tool ID: apply the same NFKC + confusable mapping
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
	if p.sessionGovernor != nil {
		p.sessionGovernor.RegisterAgentNamespace(req.AgentID)
	}
	argProvenance := p.inferArgProvenance(req.AgentID, req.SessionID, req.Args)
	if sess.IsKilled() {
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.KillSwitchActive,
			Reason:     "agent kill switch is active",
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
			token := fmt.Sprintf("%x", sha256.Sum256([]byte(req.CallID+req.ToolID+target)))[:8]
			if _, err := p.defers.DeferWithToken(token, req.AgentID, req.ToolID, routeReason); err != nil {
				// duplicate token: keep same token semantics as policy defer
			}
			return p.decide(req, Decision{
				Effect:        EffectDefer,
				ReasonCode:    reasons.RoutingUndeclaredInvocation,
				Reason:        routeReason,
				DeferToken:    token,
				PolicyVersion: engine.Version(),
			}, sess, start, argProvenance)
		}
	}

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

	// [5] Budget enforcement — check session and daily limits.
	if doc.Budget != nil {
		if denied, code, reason := p.checkBudget(req.AgentID, doc.Budget, callCount); denied {
			return p.decide(req, Decision{
				Effect:     EffectDeny,
				ReasonCode: code,
				Reason:     reason,
			}, sess, start, argProvenance)
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
			CallCount:    callCount,
			History:      historyEntries,
			CostUSD:      sess.CurrentCostUSD(),
			DailyCostUSD: sess.DailyCostUSD(),
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

	result := engine.Evaluate(req.ToolID, ctx)

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

	return p.decide(req, d, sess, start, argProvenance)
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
func (p *Pipeline) decide(req CanonicalActionRequest, d Decision, sess *session.State, start time.Time, argProvenance map[string]string) Decision {
	d.Latency = time.Since(start)
	d.AgentID = req.AgentID
	d.ToolID = req.ToolID
	d.SessionID = req.SessionID
	d.Timestamp = req.Timestamp
	d.ReasonCode = reasons.Normalize(d.ReasonCode)

	// Record metrics.
	observe.Default.RecordDecision(string(d.Effect), d.ReasonCode, d.Latency)
	if d.Effect == EffectDeny && d.IncidentCategory != "" {
		sev := d.IncidentSeverity
		if sev == "" {
			sev = "unspecified"
		}
		observe.Default.RecordIncidentPrevented(d.IncidentCategory, sev)
	}

	// [9] WAL write — fsync before returning.
	rec := p.buildRecord(req, d, argProvenance)
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
	p.recordToolOutputs(req.AgentID, req.SessionID, req.ToolID, rec.RecordID, req.Args)

	if p.routingGovernor != nil && d.Effect == EffectPermit && topologyInvokeTool(req.ToolID) && p.routingGovernor.HasManifest(req.AgentID) {
		if target := extractTargetAgentID(req.Args); target != "" {
			p.routingGovernor.RecordInvocation(req.AgentID, target, req.SessionID)
		}
	}

	// Lifecycle callback: async + fail-open, must not alter governance decisions.
	if p.callbacks != nil {
		p.callbacks.FireOnDecision(callbacks.OnDecisionPayload{
			AgentID:    req.AgentID,
			ToolID:     req.ToolID,
			Effect:     string(d.Effect),
			RuleID:     d.RuleID,
			ReasonCode: d.ReasonCode,
			RecordID:   d.DPRRecordID,
		})
	}

	// Fail-open telemetry hooks (P5): never block or alter decisions.
	if d.Effect == EffectPermit {
		principalID := ""
		if req.Principal != nil {
			principalID = req.Principal.ID
		}
		observe.Default.RecordPermitAccess(observe.AccessEvent{
			AgentID:     req.AgentID,
			SessionID:   req.SessionID,
			ToolID:      req.ToolID,
			RuleID:      d.RuleID,
			Timestamp:   req.Timestamp,
			PrincipalID: principalID,
			DPRID:       d.DPRRecordID,
		})
	}
	if d.RuleID != "" {
		observe.Default.ObserveRule(observe.RuleObservation{
			AgentID:   req.AgentID,
			SessionID: req.SessionID,
			ToolID:    req.ToolID,
			RuleID:    d.RuleID,
			Effect:    string(d.Effect),
			Timestamp: req.Timestamp,
		})
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
	if d.Effect == EffectPermit || d.Effect == EffectShadow {
		go p.accountCost(req.AgentID, req.ToolID, sess)
	}
	if p.syncer != nil {
		go p.syncer.Send(d)
	}
	if p.webhooks != nil {
		go p.emitWebhook(req, d)
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

// buildRecord constructs the DPR record for this decision.
func (p *Pipeline) buildRecord(req CanonicalActionRequest, d Decision, argProvenance map[string]string) *dpr.Record {
	p.chainLock.Lock()
	prevHash := p.chainMu[req.AgentID]
	if prevHash == "" {
		// Genesis record: deterministic chain-start marker per agent.
		prevHash = dpr.GenesisPrevHash(req.AgentID)
	}

	rec := &dpr.Record{
		SchemaVersion:      dpr.SchemaVersion,
		CARVersion:         CARVersion,
		RecordID:           uuid.New().String(),
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
		CreatedAt:          req.Timestamp,
	}
	if p.degraded != nil {
		rec.DegradedMode = p.degraded.Current().String()
	}
	setRecordCredentialMeta(rec, credentialMetaFromArgs(req.Args))
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
	if len(p.hmacKey) > 0 {
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
			CallCount:    sess.CallCount(),
			History:      historyEntries,
			CostUSD:      sess.CurrentCostUSD(),
			DailyCostUSD: sess.DailyCostUSD(),
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
			scope = strings.TrimPrefix(tag, "credential:scope:")
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

// ScanOutput runs post-execution output scanning on a tool's output.
// Adapters call this after a PERMIT'd tool completes, before returning
// the output to the agent's context. Returns the scan result which may
// contain redacted output or a denial.
func (p *Pipeline) ScanOutput(toolID, output string) postcondition.ScanResult {
	p.recordToolOutputs("", "", toolID, "", map[string]any{"output": output})
	scanner := p.currentArtifacts().postScanner
	if scanner == nil {
		return postcondition.ScanResult{Outcome: postcondition.OutcomePass, Output: output}
	}
	res := scanner.Scan(toolID, output)
	switch res.Outcome {
	case postcondition.OutcomeRedacted:
		observe.Default.RecordPostScan("REDACTED")
	case postcondition.OutcomeDenied:
		observe.Default.RecordPostScan("DENIED")
	default:
		observe.Default.RecordPostScan("pass")
	}
	return res
}

func (p *Pipeline) inferArgProvenance(agentID, sessionID string, args map[string]any) map[string]string {
	if p.provenance == nil {
		return nil
	}
	defer func() { _ = recover() }()
	out, err := p.provenance.InferArgProvenance(agentID, sessionID, args)
	if err != nil {
		return nil
	}
	return out
}

func (p *Pipeline) recordToolOutputs(agentID, sessionID, toolID, recordID string, args map[string]any) {
	if p.provenance == nil || len(args) == 0 {
		return
	}
	// Best-effort, fail-open telemetry hook.
	go func() {
		defer func() { _ = recover() }()
		const maxOutputs = 6
		emitted := 0
		for _, key := range []string{"output", "result", "response", "body", "stdout", "stderr"} {
			v, ok := args[key]
			if !ok {
				continue
			}
			if err := p.provenance.RecordToolOutput(agentID, sessionID, toolID, recordID, v); err == nil {
				emitted++
			}
			if emitted >= maxOutputs {
				return
			}
		}
	}()
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
