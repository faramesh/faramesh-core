// Package daemon implements the A2 Local Daemon adapter — a persistent gRPC
// server that runs as a long-lived sidecar process. It provides service
// discovery via mDNS, health checks, and multi-process support for scenarios
// where multiple agents on the same host share a single governance daemon.
//
// Architecture:
//
//	Agent Process → gRPC → Daemon Process → Pipeline → Decision → gRPC → Agent
//
// The daemon manages DEFER by parking the gRPC stream until approval arrives.
package daemon

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	deferPkg "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/google/uuid"
)

// Server is the A2 gRPC daemon adapter.
type Server struct {
	pipeline   *core.Pipeline
	server     *grpc.Server
	mu         sync.RWMutex
	clients    map[string]time.Time // agentID → last seen
	adminToken string

	UnimplementedFarameshDaemonServer
}

// Config holds construction parameters.
type Config struct {
	Pipeline          *core.Pipeline
	TLSConfig         *tls.Config
	PolicyAdminToken  string
	PrincipalResolver func(context.Context, string) (*principal.Identity, error)
}

// NewServer creates a new A2 daemon server.
func NewServer(cfg Config) *Server {
	s := &Server{
		pipeline:   cfg.Pipeline,
		clients:    make(map[string]time.Time),
		adminToken: strings.TrimSpace(cfg.PolicyAdminToken),
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024), // 4MB
		// This service uses plain Go structs, not generated protobuf messages.
		// Force JSON codec so manual clients can marshal/unmarshal safely.
		grpc.ForceServerCodec(jsonCodec{}),
	}
	if cfg.TLSConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(cfg.TLSConfig)))
	}
	gs := grpc.NewServer(opts...)

	RegisterFarameshDaemonServer(gs, s)

	// Register gRPC health service.
	hs := health.NewServer()
	hs.SetServingStatus("faramesh.daemon", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)

	s.server = gs
	return s
}

// Serve starts the gRPC server on the given listener.
func (s *Server) Serve(lis net.Listener) error {
	return s.server.Serve(lis)
}

// GracefulStop signals the server to stop accepting new connections
// and blocks until all in-flight RPCs complete.
func (s *Server) GracefulStop() {
	s.server.GracefulStop()
}

// Govern implements the FarameshDaemonServer interface.
// This is the main entry point for governance requests from agent processes.
func (s *Server) Govern(ctx context.Context, req *GovernRequest) (*GovernResponse, error) {
	if strings.TrimSpace(req.ApiVersion) != "" {
		major, err := requestVersionMajor(req.ApiVersion)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid api_version: %v", err)
		}
		if major != APIMajorVersion {
			return nil, status.Errorf(codes.Unimplemented, "unsupported api_version major %d (supported major: %d)", major, APIMajorVersion)
		}
	}
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	if req.ToolId == "" {
		return nil, status.Error(codes.InvalidArgument, "tool_id is required")
	}

	// Track client activity.
	s.mu.Lock()
	s.clients[req.AgentId] = time.Now()
	s.mu.Unlock()

	// Parse args from JSON.
	args := make(map[string]any)
	if req.ArgsJson != "" {
		if err := json.Unmarshal([]byte(req.ArgsJson), &args); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid args_json: %v", err)
		}
	}

	callID := req.CallId
	if callID == "" {
		callID = uuid.New().String()
	}

	car := core.CanonicalActionRequest{
		CallID:             callID,
		AgentID:            req.AgentId,
		SessionID:          req.SessionId,
		ToolID:             req.ToolId,
		Args:               args,
		ExecutionTimeoutMS: req.ExecutionTimeoutMs,
		Timestamp:          time.Now(),
		InterceptAdapter:   "daemon",
	}

	decision := s.pipeline.Evaluate(car)

	resp := &GovernResponse{
		Effect:           string(decision.Effect),
		RuleId:           decision.RuleID,
		ReasonCode:       reasons.Normalize(decision.ReasonCode),
		Reason:           decision.Reason,
		DeferToken:       decision.DeferToken,
		PolicyVersion:    decision.PolicyVersion,
		LatencyMs:        decision.Latency.Milliseconds(),
		DaemonApiVersion: APIVersion,
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-faramesh-api-version", APIVersion))

	// If DEFER, block until approval or timeout.
	if decision.Effect == core.EffectDefer && req.WaitForApproval {
		approved, err := s.waitForApproval(ctx, decision.DeferToken)
		if err != nil {
			return nil, status.Errorf(codes.DeadlineExceeded, "defer timeout: %v", err)
		}
		if approved {
			// TOCTOU guard: re-evaluate at execution time against current policy/state.
			reevalReq := car
			reevalReq.CallID = car.CallID + "-resume"
			reeval := s.pipeline.Evaluate(reevalReq)
			if reeval.Effect == core.EffectPermit || reeval.Effect == core.EffectShadow {
				resp.Effect = string(core.EffectPermit)
				resp.ReasonCode = reasons.ApprovalGranted
				resp.Reason = "action approved and re-evaluated successfully"
			} else {
				resp.Effect = string(core.EffectDeny)
				resp.ReasonCode = reasons.RuleDeny
				resp.Reason = "approval granted but execution-time re-evaluation denied action"
			}
		} else {
			resp.Effect = string(core.EffectDeny)
			resp.ReasonCode = reasons.ApprovalDenied
			resp.Reason = "action denied by human operator"
		}
	}

	return resp, nil
}

// Kill implements the FarameshDaemonServer interface.
func (s *Server) Kill(ctx context.Context, req *KillRequest) (*KillResponse, error) {
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	s.pipeline.SessionManager().Kill(req.AgentId)
	return &KillResponse{Success: true}, nil
}

// PushPolicy validates, compiles, and atomically applies a new policy bundle.
// Access is restricted to local callers presenting the configured admin token.
func (s *Server) PushPolicy(ctx context.Context, req *PushPolicyRequest) (*PushPolicyResponse, error) {
	if !isLocalPeer(ctx) {
		return nil, status.Error(codes.PermissionDenied, "push policy is restricted to local callers")
	}
	if s.adminToken == "" {
		return nil, status.Error(codes.PermissionDenied, "policy push admin token is not configured")
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.AdminToken)), []byte(s.adminToken)) != 1 {
		return nil, status.Error(codes.PermissionDenied, "invalid admin token")
	}
	if strings.TrimSpace(req.PolicyYaml) == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_yaml is required")
	}

	doc, version, err := policy.LoadBytes([]byte(req.PolicyYaml))
	if err != nil {
		return &PushPolicyResponse{
			Applied: false,
			Errors:  []string{err.Error()},
		}, nil
	}
	if errs := policy.ValidationErrorsOnly(policy.Validate(doc)); len(errs) > 0 {
		return &PushPolicyResponse{
			Applied: false,
			Errors:  errs,
		}, nil
	}
	newEngine, err := policy.NewEngine(doc, version)
	if err != nil {
		return &PushPolicyResponse{
			Applied: false,
			Errors:  []string{err.Error()},
		}, nil
	}
	if err := s.pipeline.ApplyPolicyBundle(doc, newEngine); err != nil {
		return &PushPolicyResponse{
			Applied: false,
			Errors:  []string{err.Error()},
		}, nil
	}
	return &PushPolicyResponse{
		Applied:       true,
		PolicyVersion: version,
		PolicyHash:    version,
	}, nil
}

// ActiveClients returns the number of recently active agent processes.
func (s *Server) ActiveClients(window time.Duration) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-window)
	count := 0
	for _, lastSeen := range s.clients {
		if lastSeen.After(cutoff) {
			count++
		}
	}
	return count
}

func (s *Server) waitForApproval(ctx context.Context, token string) (bool, error) {
	wf := s.pipeline.DeferWorkflow()
	if wf == nil {
		return false, fmt.Errorf("no defer workflow configured")
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			st, pending := wf.Status(token)
			if pending {
				continue
			}
			if st == deferPkg.StatusApproved {
				return true, nil
			}
			return false, nil
			// Still pending — continue polling.
		}
	}
}

func isLocalPeer(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.Addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		host = p.Addr.String()
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
