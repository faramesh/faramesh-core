// Package daemon implements the A2 Local Daemon adapter — a persistent gRPC
// server that runs as a long-lived sidecar process. It provides service
// discovery via mDNS, health checks, and multi-process support for scenarios
// where multiple agents on the same host share a single governance daemon.
//
// Architecture:
//   Agent Process → gRPC → Daemon Process → Pipeline → Decision → gRPC → Agent
//
// The daemon manages DEFER by parking the gRPC stream until approval arrives.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/faramesh/faramesh-core/internal/core"
	deferPkg "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/google/uuid"
)

// Server is the A2 gRPC daemon adapter.
type Server struct {
	pipeline *core.Pipeline
	server   *grpc.Server
	mu       sync.RWMutex
	clients  map[string]time.Time // agentID → last seen

	UnimplementedFarameshDaemonServer
}

// Config holds construction parameters.
type Config struct {
	Pipeline *core.Pipeline
}

// NewServer creates a new A2 daemon server.
func NewServer(cfg Config) *Server {
	s := &Server{
		pipeline: cfg.Pipeline,
		clients:  make(map[string]time.Time),
	}

	gs := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024), // 4MB
	)

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
		CallID:           callID,
		AgentID:          req.AgentId,
		SessionID:        req.SessionId,
		ToolID:           req.ToolId,
		Args:             args,
		Timestamp:        time.Now(),
		InterceptAdapter: "daemon",
	}

	decision := s.pipeline.Evaluate(car)

	resp := &GovernResponse{
		Effect:        string(decision.Effect),
		RuleId:        decision.RuleID,
		ReasonCode:    decision.ReasonCode,
		Reason:        decision.Reason,
		DeferToken:    decision.DeferToken,
		PolicyVersion: decision.PolicyVersion,
		LatencyMs:     decision.Latency.Milliseconds(),
	}

	// If DEFER, block until approval or timeout.
	if decision.Effect == core.EffectDefer && req.WaitForApproval {
		approved, err := s.waitForApproval(ctx, decision.DeferToken)
		if err != nil {
			return nil, status.Errorf(codes.DeadlineExceeded, "defer timeout: %v", err)
		}
		if approved {
			resp.Effect = string(core.EffectPermit)
			resp.ReasonCode = "DEFER_APPROVED"
			resp.Reason = "action approved by human operator"
		} else {
			resp.Effect = string(core.EffectDeny)
			resp.ReasonCode = "DEFER_DENIED"
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
