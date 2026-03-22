package observe

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	GovernanceLogSchema        = "faramesh.governance"
	GovernanceLogSchemaVersion = "1.0"

	EventGovernDecision       = "govern_decision"
	EventPolicyReload         = "policy_reload"
	EventDeferResolveConflict = "defer_resolution_conflict"
	EventExecutionTimeoutDeny = "execution_timeout_denial"
)

// EmitGovernanceLog preserves existing log messages while enforcing a
// versioned, machine-parseable event envelope for governance events.
func EmitGovernanceLog(log *zap.Logger, level zapcore.Level, message string, event string, fields ...zap.Field) {
	if log == nil {
		log = zap.NewNop()
	}
	envelope := []zap.Field{
		zap.String("log_schema", GovernanceLogSchema),
		zap.String("log_schema_version", GovernanceLogSchemaVersion),
		zap.String("event", event),
	}
	envelope = append(envelope, fields...)
	switch level {
	case zapcore.DebugLevel:
		log.Debug(message, envelope...)
	case zapcore.WarnLevel:
		log.Warn(message, envelope...)
	case zapcore.ErrorLevel:
		log.Error(message, envelope...)
	default:
		log.Info(message, envelope...)
	}
}
