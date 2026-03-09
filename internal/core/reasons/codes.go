// Package reasons defines the complete enumeration of DPR reason codes.
// This is part of the DPR v1.0 specification. Every reason_code value in
// a DPR record must be drawn from this enumeration.
//
// Third-party tools that parse DPR records depend on the stability of
// this enumeration. New codes require a DPR spec minor version bump.
// Renamed codes require a major version bump.
package reasons

const (
	// Policy outcome codes
	RulePermit   = "RULE_PERMIT"    // Action permitted by explicit policy rule
	RuleDeny     = "RULE_DENY"      // Action denied by explicit policy rule
	RuleDefer    = "RULE_DEFER"     // Action deferred by explicit policy rule
	UnmatchedDeny = "UNMATCHED_DENY" // No rule matched; default deny applied
	ShadowDeny   = "SHADOW_DENY"    // Shadow mode: would have been denied
	ShadowDefer  = "SHADOW_DEFER"   // Shadow mode: would have been deferred

	// Pre-execution scanner codes
	ShellClassifierRmRf        = "SHELL_CLASSIFIER_RM_RF"
	ShellClassifierPipeChain   = "SHELL_CLASSIFIER_PIPE_CHAIN"
	ShellClassifierPrivEsc     = "SHELL_CLASSIFIER_PRIVILEGE_ESC"
	ShellClassifierNetExfil    = "SHELL_CLASSIFIER_NETWORK_EXFIL"
	ShellClassifierCrontab     = "SHELL_CLASSIFIER_CRONTAB_MOD"
	ShellClassifierSSHKey      = "SHELL_CLASSIFIER_SSH_KEY_OP"
	ShellClassifierEtcMod      = "SHELL_CLASSIFIER_ETC_MOD"
	PathTraversal              = "PATH_TRAVERSAL"
	SQLInjection               = "SQL_INJECTION"
	CodeExecutionInArgs        = "CODE_EXECUTION_IN_ARGS"
	URLDomainBlocked           = "URL_DOMAIN_BLOCKED"
	SensitiveFilePath          = "SENSITIVE_FILE_PATH"
	SchemaValidationFail       = "SCHEMA_VALIDATION_FAIL"
	HighEntropySecret          = "HIGH_ENTROPY_SECRET"
	MultimodalInjection        = "MULTIMODAL_INJECTION"
	ArrayCardinalityExceeded   = "ARRAY_CARDINALITY_EXCEEDED"

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
	SessionToolLimit         = "SESSION_TOOL_LIMIT"
	SessionDailyCostLimit    = "SESSION_DAILY_COST_LIMIT"
	SessionAttemptLimit      = "SESSION_ATTEMPT_LIMIT"
	SessionRollingLimit      = "SESSION_ROLLING_LIMIT"
	CrossSessionPrincipalLimit = "CROSS_SESSION_PRINCIPAL_LIMIT"
	BehavioralAnomalyAlert   = "BEHAVIORAL_ANOMALY_ALERT"
	BehavioralAnomalyCritical = "BEHAVIORAL_ANOMALY_CRITICAL"
	LoopDetection            = "LOOP_DETECTION"
	AgentLoopDetected        = "AGENT_LOOP_DETECTED"

	// Governance infrastructure codes
	EvaluationTimeout          = "EVALUATION_TIMEOUT"
	SessionStateUnavailable    = "SESSION_STATE_UNAVAILABLE"
	ContextStale               = "CONTEXT_STALE"
	ContextMissing             = "CONTEXT_MISSING"
	ContextInconsistent        = "CONTEXT_INCONSISTENT"
	ContextTimeout             = "CONTEXT_TIMEOUT"
	PolicyLoadError            = "POLICY_LOAD_ERROR"
	ChainIntegrityViolation    = "CHAIN_INTEGRITY_VIOLATION"
	WALWriteFailure            = "WAL_WRITE_FAILURE"
	KillSwitchActive           = "KILL_SWITCH_ACTIVE"
	ScannerDeny                = "SCANNER_DENY"
	UnknownEffect              = "UNKNOWN_EFFECT"
	DefaultEffect              = "DEFAULT_EFFECT"

	// Identity and delegation codes
	IdentityUnverified         = "IDENTITY_UNVERIFIED"
	IdentityImpersonation      = "IDENTITY_IMPERSONATION"
	DelegationExceedsAuthority = "DELEGATION_EXCEEDS_AUTHORITY"
	DelegationDepthExceeded    = "DELEGATION_DEPTH_EXCEEDED"
	DelegationOriginBlocked    = "DELEGATION_ORIGIN_BLOCKED"
	PrincipalElevationExpired  = "PRINCIPAL_ELEVATION_EXPIRED"
	PrincipalRevoked           = "PRINCIPAL_REVOKED"
	OutOfPhaseToolCall         = "OUT_OF_PHASE_TOOL_CALL"

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
	CacheHitPermit          = "CACHE_HIT_PERMIT"
	CacheEvictedKillSwitch  = "CACHE_EVICTED_KILL_SWITCH"

	// Output governance codes
	OutputSchemaDeny  = "OUTPUT_SCHEMA_DENY"
	OutputSchemaDefer = "OUTPUT_SCHEMA_DEFER"

	// Budget codes (distinct from session limits)
	BudgetDailyExceeded   = "BUDGET_DAILY_EXCEEDED"
	BudgetSessionExceeded = "BUDGET_SESSION_EXCEEDED"
	BudgetRollingExceeded = "BUDGET_ROLLING_EXCEEDED"
)
