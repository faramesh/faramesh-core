// Package reasons defines the complete enumeration of DPR reason codes.
// This is part of the DPR v1.0 specification. Every reason_code value in
// a DPR record must be drawn from this enumeration.
//
// Third-party tools that parse DPR records depend on the stability of
// this enumeration. New codes require a DPR spec minor version bump.
// Renamed codes require a major version bump.
package reasons

import (
	"fmt"
	"slices"
	"strings"
)

const (
	// UnknownReasonCode is the safe fallback when an unknown code is encountered.
	UnknownReasonCode = "UNKNOWN_REASON_CODE"

	// Policy outcome codes
	RulePermit    = "RULE_PERMIT"    // Action permitted by explicit policy rule
	RuleDeny      = "RULE_DENY"      // Action denied by explicit policy rule
	RuleDefer     = "RULE_DEFER"     // Action deferred by explicit policy rule
	UnmatchedDeny = "UNMATCHED_DENY" // No rule matched; default deny applied
	ShadowDeny    = "SHADOW_DENY"    // Shadow mode: would have been denied
	ShadowDefer   = "SHADOW_DEFER"   // Shadow mode: would have been deferred

	// Pre-execution scanner codes
	ShellClassifierRmRf      = "SHELL_CLASSIFIER_RM_RF"
	ShellClassifierPipeChain = "SHELL_CLASSIFIER_PIPE_CHAIN"
	ShellClassifierPrivEsc   = "SHELL_CLASSIFIER_PRIVILEGE_ESC"
	ShellClassifierNetExfil  = "SHELL_CLASSIFIER_NETWORK_EXFIL"
	ShellClassifierCrontab   = "SHELL_CLASSIFIER_CRONTAB_MOD"
	ShellClassifierSSHKey    = "SHELL_CLASSIFIER_SSH_KEY_OP"
	ShellClassifierEtcMod    = "SHELL_CLASSIFIER_ETC_MOD"
	PathTraversal            = "PATH_TRAVERSAL"
	SQLInjection             = "SQL_INJECTION"
	CodeExecutionInArgs      = "CODE_EXECUTION_IN_ARGS"
	URLDomainBlocked         = "URL_DOMAIN_BLOCKED"
	SensitiveFilePath        = "SENSITIVE_FILE_PATH"
	SchemaValidationFail     = "SCHEMA_VALIDATION_FAIL"
	HighEntropySecret        = "HIGH_ENTROPY_SECRET"
	MultimodalInjection      = "MULTIMODAL_INJECTION"
	ArrayCardinalityExceeded = "ARRAY_CARDINALITY_EXCEEDED"

	// Post-execution scanner codes
	OutputSecretAWSKey        = "OUTPUT_SECRET_AWS_KEY"
	OutputSecretGitHubPAT     = "OUTPUT_SECRET_GITHUB_PAT"
	OutputSecretGCPSA         = "OUTPUT_SECRET_GCP_SA"
	OutputSecretAzureConn     = "OUTPUT_SECRET_AZURE_CONN"
	OutputSecretDatabaseURI   = "OUTPUT_SECRET_DATABASE_URI"
	OutputSecretSSHKey        = "OUTPUT_SECRET_SSH_KEY"
	OutputSecretOpenAIKey     = "OUTPUT_SECRET_OPENAI_KEY"
	OutputSecretAnthropicKey  = "OUTPUT_SECRET_ANTHROPIC_KEY"
	OutputSecretBearerToken   = "OUTPUT_SECRET_BEARER_TOKEN"
	OutputPIIEmail            = "OUTPUT_PII_EMAIL"
	OutputPIIPhone            = "OUTPUT_PII_PHONE"
	OutputPIISSN              = "OUTPUT_PII_SSN"
	OutputPIICreditCard       = "OUTPUT_PII_CREDIT_CARD"
	OutputPIIIPAddress        = "OUTPUT_PII_IP_ADDRESS"
	OutputPIINPI              = "OUTPUT_PII_NPI"
	OutputPIIIBAN             = "OUTPUT_PII_IBAN"
	OutputInjectionIgnorePrev = "OUTPUT_INJECTION_IGNORE_PREV"
	OutputSizeExceeded        = "OUTPUT_SIZE_EXCEEDED"

	// Session and budget codes
	SessionToolLimit           = "SESSION_TOOL_LIMIT"
	SessionDailyCostLimit      = "SESSION_DAILY_COST_LIMIT"
	SessionAttemptLimit        = "SESSION_ATTEMPT_LIMIT"
	SessionRollingLimit        = "SESSION_ROLLING_LIMIT"
	SessionStateWriteBlocked   = "SESSION_STATE_WRITE_BLOCKED"
	CrossSessionPrincipalLimit = "CROSS_SESSION_PRINCIPAL_LIMIT"
	BehavioralAnomalyAlert     = "BEHAVIORAL_ANOMALY_ALERT"
	BehavioralAnomalyCritical  = "BEHAVIORAL_ANOMALY_CRITICAL"
	LoopDetection              = "LOOP_DETECTION"
	AgentLoopDetected          = "AGENT_LOOP_DETECTED"

	// Governance infrastructure codes
	EvaluationTimeout               = "EVALUATION_TIMEOUT"
	SessionStateUnavailable         = "SESSION_STATE_UNAVAILABLE"
	ContextStale                    = "CONTEXT_STALE"
	ContextMissing                  = "CONTEXT_MISSING"
	ContextInconsistent             = "CONTEXT_INCONSISTENT"
	ContextTimeout                  = "CONTEXT_TIMEOUT"
	ExecutionTimeoutInvalid         = "EXECUTION_TIMEOUT_INVALID"
	ExecutionTimeoutRequired        = "EXECUTION_TIMEOUT_REQUIRED"
	ExecutionTimeoutPolicyViolation = "EXECUTION_TIMEOUT_POLICY_VIOLATION"
	PolicyLoadError                 = "POLICY_LOAD_ERROR"
	GovernanceDoubleWrapDenied      = "GOVERNANCE_DOUBLE_WRAP_DENIED"
	ChainIntegrityViolation         = "CHAIN_INTEGRITY_VIOLATION"
	WALWriteFailure                 = "WAL_WRITE_FAILURE"
	KillSwitchActive                = "KILL_SWITCH_ACTIVE"
	ScannerDeny                     = "SCANNER_DENY"
	UnknownEffect                   = "UNKNOWN_EFFECT"
	DefaultEffect                   = "DEFAULT_EFFECT"

	// Identity and delegation codes
	IdentityUnverified             = "IDENTITY_UNVERIFIED"
	IdentityImpersonation          = "IDENTITY_IMPERSONATION"
	DelegationExceedsAuthority     = "DELEGATION_EXCEEDS_AUTHORITY"
	DelegationDepthExceeded        = "DELEGATION_DEPTH_EXCEEDED"
	DelegationOriginBlocked        = "DELEGATION_ORIGIN_BLOCKED"
	PrincipalElevationExpired      = "PRINCIPAL_ELEVATION_EXPIRED"
	PrincipalRevoked               = "PRINCIPAL_REVOKED"
	PrincipalVerificationUntrusted = "PRINCIPAL_VERIFICATION_UNTRUSTED"
	OutOfPhaseToolCall             = "OUT_OF_PHASE_TOOL_CALL"
	OutOfWorkflowStepToolCall      = "OUT_OF_WORKFLOW_STEP_TOOL_CALL"
	UnknownWorkflowStep            = "UNKNOWN_WORKFLOW_STEP"
	IsolationRequired              = "ISOLATION_REQUIRED"

	// Approval codes
	ApprovalGranted  = "APPROVAL_GRANTED"
	ApprovalDenied   = "APPROVAL_DENIED"
	ApprovalTimeout  = "APPROVAL_TIMEOUT"
	ApprovalModified = "APPROVAL_MODIFIED"

	// Compensation codes
	CompensationExecuted = "COMPENSATION_EXECUTED"
	CompensationFailed   = "COMPENSATION_FAILED"
	CompensationPartial  = "COMPENSATION_PARTIAL"

	// Cache codes
	CacheHitPermit         = "CACHE_HIT_PERMIT"
	CacheEvictedKillSwitch = "CACHE_EVICTED_KILL_SWITCH"

	// Output governance codes
	OutputSchemaDeny  = "OUTPUT_SCHEMA_DENY"
	OutputSchemaDefer = "OUTPUT_SCHEMA_DEFER"

	// Budget codes (distinct from session limits)
	BudgetDailyExceeded   = "BUDGET_DAILY_EXCEEDED"
	BudgetSessionExceeded = "BUDGET_SESSION_EXCEEDED"
	BudgetRollingExceeded = "BUDGET_ROLLING_EXCEEDED"

	// Degraded mode codes
	GovernanceDegradedStateless = "GOVERNANCE_DEGRADED_STATELESS"
	GovernanceDegradedMinimal   = "GOVERNANCE_DEGRADED_MINIMAL"
	GovernanceDegradedEmergency = "GOVERNANCE_DEGRADED_EMERGENCY"
	GovernanceShutdown          = "GOVERNANCE_SHUTDOWN"
	DPRBufferOverflow           = "DPR_BUFFER_OVERFLOW"

	// Workflow phase codes
	PhaseTransitionPermit = "PHASE_TRANSITION_PERMIT"
	PhaseTransitionDefer  = "PHASE_TRANSITION_DEFER"

	// Custom operator codes
	OperatorTimeout = "OPERATOR_TIMEOUT"

	// Multi-agent codes
	SessionStateNamespaceViolation   = "SESSION_STATE_NAMESPACE_VIOLATION"
	PipelineTamperDetected           = "PIPELINE_TAMPER_DETECTED"
	PriorPhaseIncomplete             = "PRIOR_PHASE_INCOMPLETE"
	AggregateBudgetExceeded          = "AGGREGATE_BUDGET_EXCEEDED"
	ParallelAgentCancelled           = "PARALLEL_AGENT_CANCELLED"
	SyncGateIncomplete               = "SYNC_GATE_INCOMPLETE"
	LoopConvergenceEvasion           = "LOOP_CONVERGENCE_EVASION"
	LoopMaxIterations                = "LOOP_MAX_ITERATIONS"
	LoopMaxCost                      = "LOOP_MAX_COST"
	LoopMaxDuration                  = "LOOP_MAX_DURATION"
	RoutingUndeclaredInvocation      = "ROUTING_UNDECLARED_INVOCATION"
	RoutingManifestViolation         = "ROUTING_MANIFEST_VIOLATION"
	RoutingInvocationSubPolicyDenied = "ROUTING_INVOCATION_SUB_POLICY_DENIED"

	// Chain analysis / lazy validation codes
	ProbableDataExfiltration     = "PROBABLE_DATA_EXFILTRATION"
	CredentialReuseForEscalation = "CREDENTIAL_REUSE_FOR_ESCALATION"

	// Principal lifecycle codes
	PrincipalElevationApproved = "PRINCIPAL_ELEVATION_APPROVED"
	PrincipalElevationDenied   = "PRINCIPAL_ELEVATION_DENIED"

	// Bootstrapping codes
	GovernanceBootstrapRequired = "GOVERNANCE_BOOTSTRAP_REQUIRED"

	// Callback codes
	CallbackError            = "CALLBACK_ERROR"
	CallbackUnsafeArgsAccess = "CALLBACK_UNSAFE_ARGS_ACCESS"
	TelemetryHookError       = "TELEMETRY_HOOK_ERROR"

	// Policy source codes
	PolicyValidationFailed = "POLICY_VALIDATION_FAILED"
	PolicySourceDegraded   = "POLICY_SOURCE_DEGRADED"
)

var canonical = map[string]struct{}{
	UnknownReasonCode: {},
	RulePermit:        {},
	RuleDeny:          {},
	RuleDefer:         {},
	UnmatchedDeny:     {},
	ShadowDeny:        {},
	ShadowDefer:       {},

	ShellClassifierRmRf:      {},
	ShellClassifierPipeChain: {},
	ShellClassifierPrivEsc:   {},
	ShellClassifierNetExfil:  {},
	ShellClassifierCrontab:   {},
	ShellClassifierSSHKey:    {},
	ShellClassifierEtcMod:    {},
	PathTraversal:            {},
	SQLInjection:             {},
	CodeExecutionInArgs:      {},
	URLDomainBlocked:         {},
	SensitiveFilePath:        {},
	SchemaValidationFail:     {},
	HighEntropySecret:        {},
	MultimodalInjection:      {},
	ArrayCardinalityExceeded: {},

	OutputSecretAWSKey:        {},
	OutputSecretGitHubPAT:     {},
	OutputSecretGCPSA:         {},
	OutputSecretAzureConn:     {},
	OutputSecretDatabaseURI:   {},
	OutputSecretSSHKey:        {},
	OutputSecretOpenAIKey:     {},
	OutputSecretAnthropicKey:  {},
	OutputSecretBearerToken:   {},
	OutputPIIEmail:            {},
	OutputPIIPhone:            {},
	OutputPIISSN:              {},
	OutputPIICreditCard:       {},
	OutputPIIIPAddress:        {},
	OutputPIINPI:              {},
	OutputPIIIBAN:             {},
	OutputInjectionIgnorePrev: {},
	OutputSizeExceeded:        {},

	SessionToolLimit:           {},
	SessionDailyCostLimit:      {},
	SessionAttemptLimit:        {},
	SessionRollingLimit:        {},
	SessionStateWriteBlocked:   {},
	CrossSessionPrincipalLimit: {},
	BehavioralAnomalyAlert:     {},
	BehavioralAnomalyCritical:  {},
	LoopDetection:              {},
	AgentLoopDetected:          {},

	EvaluationTimeout:               {},
	SessionStateUnavailable:         {},
	ContextStale:                    {},
	ContextMissing:                  {},
	ContextInconsistent:             {},
	ContextTimeout:                  {},
	ExecutionTimeoutInvalid:         {},
	ExecutionTimeoutRequired:        {},
	ExecutionTimeoutPolicyViolation: {},
	PolicyLoadError:                 {},
	GovernanceDoubleWrapDenied:      {},
	ChainIntegrityViolation:         {},
	WALWriteFailure:                 {},
	KillSwitchActive:                {},
	ScannerDeny:                     {},
	UnknownEffect:                   {},
	DefaultEffect:                   {},

	IdentityUnverified:             {},
	IdentityImpersonation:          {},
	DelegationExceedsAuthority:     {},
	DelegationDepthExceeded:        {},
	DelegationOriginBlocked:        {},
	PrincipalElevationExpired:      {},
	PrincipalRevoked:               {},
	PrincipalVerificationUntrusted: {},
	OutOfPhaseToolCall:             {},
	OutOfWorkflowStepToolCall:      {},
	UnknownWorkflowStep:            {},
	IsolationRequired:              {},

	ApprovalGranted:  {},
	ApprovalDenied:   {},
	ApprovalTimeout:  {},
	ApprovalModified: {},

	CompensationExecuted: {},
	CompensationFailed:   {},
	CompensationPartial:  {},

	CacheHitPermit:         {},
	CacheEvictedKillSwitch: {},

	OutputSchemaDeny:  {},
	OutputSchemaDefer: {},

	BudgetDailyExceeded:   {},
	BudgetSessionExceeded: {},
	BudgetRollingExceeded: {},

	GovernanceDegradedStateless: {},
	GovernanceDegradedMinimal:   {},
	GovernanceDegradedEmergency: {},
	GovernanceShutdown:          {},
	DPRBufferOverflow:           {},

	PhaseTransitionPermit: {},
	PhaseTransitionDefer:  {},

	OperatorTimeout: {},

	SessionStateNamespaceViolation:   {},
	PipelineTamperDetected:           {},
	PriorPhaseIncomplete:             {},
	AggregateBudgetExceeded:          {},
	ParallelAgentCancelled:           {},
	SyncGateIncomplete:               {},
	LoopConvergenceEvasion:           {},
	LoopMaxIterations:                {},
	LoopMaxCost:                      {},
	LoopMaxDuration:                  {},
	RoutingUndeclaredInvocation:      {},
	RoutingManifestViolation:         {},
	RoutingInvocationSubPolicyDenied: {},

	ProbableDataExfiltration:     {},
	CredentialReuseForEscalation: {},

	PrincipalElevationApproved: {},
	PrincipalElevationDenied:   {},

	GovernanceBootstrapRequired: {},

	CallbackError:            {},
	CallbackUnsafeArgsAccess: {},
	TelemetryHookError:       {},

	PolicyValidationFailed: {},
	PolicySourceDegraded:   {},
}

// CanonicalCodes returns all canonical reason codes in deterministic order.
func CanonicalCodes() []string {
	codes := make([]string, 0, len(canonical))
	for code := range canonical {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// IsKnown reports whether code is part of the canonical reason-code registry.
func IsKnown(code string) bool {
	_, ok := canonical[strings.TrimSpace(code)]
	return ok
}

// Normalize returns a canonical code, or UnknownReasonCode for unknown/empty values.
func Normalize(code string) string {
	c := strings.TrimSpace(code)
	if c == "" {
		return UnknownReasonCode
	}
	if IsKnown(c) {
		return c
	}
	return UnknownReasonCode
}

// Validate rejects unknown reason codes for strict serialization paths.
func Validate(code string) error {
	if IsKnown(code) {
		return nil
	}
	return fmt.Errorf("unknown reason code: %q", strings.TrimSpace(code))
}
