// Package serverless implements the A4 Serverless adapter — an in-process
// library for Lambda, Cloud Functions, and Cloud Run. Designed for cold-start
// optimization (<50ms init), env-based config, and SQS-backed DEFER polling.
//
// Architecture:
//   Agent Process ←→ [In-Process Faramesh] → Pipeline → Decision
//
// No network hop — the governance engine runs inside the serverless function.
// Policy is loaded from an environment variable or embedded in the deployment.
package serverless

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Guard is the serverless governance guard. It is designed to be
// initialized once during cold start and reused across invocations.
type Guard struct {
	pipeline *core.Pipeline
	config   GuardConfig
}

// GuardConfig holds initialization parameters.
type GuardConfig struct {
	// PolicyYAML is inline policy YAML (alternative to PolicyPath).
	PolicyYAML string

	// PolicyPath is the file path to the policy YAML.
	PolicyPath string

	// AgentID is the agent identity (falls back to FARAMESH_AGENT_ID env var).
	AgentID string

	// DPRPath is the local SQLite path for DPR records (optional).
	// Defaults to /tmp/faramesh-dpr.db for Lambda's writable /tmp.
	DPRPath string
}

// NewGuard creates a serverless governance guard from config.
// Cold-start optimized: policy is compiled from YAML without network calls.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	// Resolve agent ID from config or environment.
	agentID := cfg.AgentID
	if agentID == "" {
		agentID = os.Getenv("FARAMESH_AGENT_ID")
	}
	if agentID == "" {
		agentID = "serverless-agent"
	}

	// Load policy from YAML string or file.
	var policyYAML []byte
	if cfg.PolicyYAML != "" {
		policyYAML = []byte(cfg.PolicyYAML)
	} else if cfg.PolicyPath != "" {
		var err error
		policyYAML, err = os.ReadFile(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
	} else if envPolicy := os.Getenv("FARAMESH_POLICY"); envPolicy != "" {
		policyYAML = []byte(envPolicy)
	} else {
		return nil, fmt.Errorf("no policy provided: set PolicyYAML, PolicyPath, or FARAMESH_POLICY env var")
	}

	var doc policy.Doc
	if err := yaml.Unmarshal(policyYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}

	version := fmt.Sprintf("sha256:%x", sha256.Sum256(policyYAML))[:16]
	engine, err := policy.NewEngine(&doc, version)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	// Open SQLite DPR store at writable path.
	dprPath := cfg.DPRPath
	if dprPath == "" {
		dprPath = "/tmp/faramesh-dpr.db"
	}
	store, err := dpr.OpenStore(dprPath)
	if err != nil {
		// Non-fatal: proceed without SQLite.
		store = nil
	}

	pipeline := core.NewPipeline(core.Config{
		Engine: policy.NewAtomicEngine(engine),
		Store:  store,
	})

	return &Guard{
		pipeline: pipeline,
		config:   cfg,
	}, nil
}

// Govern evaluates a tool call and returns the governance decision.
// This is the primary API for serverless agents.
func (g *Guard) Govern(ctx context.Context, toolID string, args map[string]any) core.Decision {
	agentID := g.config.AgentID
	if agentID == "" {
		agentID = os.Getenv("FARAMESH_AGENT_ID")
	}

	car := core.CanonicalActionRequest{
		CallID:           uuid.New().String(),
		AgentID:          agentID,
		SessionID:        sessionIDFromContext(ctx),
		ToolID:           toolID,
		Args:             args,
		Timestamp:        time.Now(),
		InterceptAdapter: "serverless",
	}

	return g.pipeline.Evaluate(car)
}

// GovernJSON is a convenience method that accepts JSON-encoded args.
func (g *Guard) GovernJSON(ctx context.Context, toolID string, argsJSON []byte) (core.Decision, error) {
	var args map[string]any
	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &args); err != nil {
			return core.Decision{}, fmt.Errorf("parse args JSON: %w", err)
		}
	}
	return g.Govern(ctx, toolID, args), nil
}

// sessionIDFromContext extracts a session ID from context or generates one.
func sessionIDFromContext(ctx context.Context) string {
	// Check for Lambda request ID in context.
	if reqID := os.Getenv("AWS_REQUEST_ID"); reqID != "" {
		return reqID
	}
	// Check for GCP function execution ID.
	if execID := os.Getenv("FUNCTION_EXECUTION_ID"); execID != "" {
		return execID
	}
	return uuid.New().String()
}
