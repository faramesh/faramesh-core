// Package sdk implements the A1 SDK adapter: a newline-delimited JSON
// protocol over a Unix domain socket. The Python/Node/Go SDK connects here
// to submit tool calls and receive governance decisions.
//
// Protocol:
//
//	Client → Server: {"type":"govern","call_id":"...","agent_id":"...","session_id":"...","tool_id":"...","args":{...}}\n
//	Server → Client: {"call_id":"...","effect":"PERMIT|DENY|DEFER","denial_token":"...","retry_permitted":false,"defer_token":"...","latency_ms":11}\n
//
//	Client → Server: {"type":"poll_defer","agent_id":"...","defer_token":"..."}\n
//	Server → Client: {"defer_token":"...","status":"pending|approved|denied|expired|unknown"}\n
//
//	Client → Server: {"type":"approve_defer","defer_token":"...","approved":true,"reason":"..."}\n
//	Server → Client: {"ok":true}\n
//
//	Client → Server: {"type":"standing_grant_add","admin_token":"<daemon secret>","agent_id":"...","tool_pattern":"pay/*","ttl_seconds":3600,"max_uses":1,"issued_by":"ops",...}\n
//	Server → Client: {"ok":true,"grant":{...}}\n
//
//	Client → Server: {"type":"standing_grant_revoke","admin_token":"<daemon secret>","grant_id":"stg_..."}\n
//	Server → Client: {"ok":true}\n
//
//	Client → Server: {"type":"standing_grant_list","admin_token":"<daemon secret>"}\n
//	Server → Client: {"ok":true,"grants":[...]}\n
//
//	admin_token must match the daemon's configured standing/policy admin token (see SetStandingAdminToken). If the daemon has no admin token configured, standing grant APIs are disabled.
//
//	Client → Server: {"type":"kill","agent_id":"...","admin_token":"<daemon secret>"}\n
//	Server → Client: {"ok":true}\n
//
//	Client → Server: {"type":"audit_subscribe"}\n
//	Server → Client: (stream of decision JSON objects, one per line, until connection closes)\n
//
//	Client → Server: {"type":"callback_subscribe"}\n
//	Server → Client: (stream of callback event JSON objects, one per line, until connection closes)\n
//
//	Client → Server: {"type":"scan_output","agent_id":"...","tool_id":"...","output":"..."}\n
//	Server → Client: {"outcome":"PASS|REDACTED|DENIED|WARNED","sanitized_output":"...","reason_code":"...","reason":"..."}\n
package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	"github.com/faramesh/faramesh-core/internal/core/delegate"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/google/uuid"
	"go.uber.org/zap/zapcore"
)

var SocketPath = defaultSocketPath()

func defaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(os.TempDir(), "faramesh", "runtime", "faramesh.sock")
	}
	return filepath.Join(home, ".faramesh", "runtime", "faramesh.sock")
}

// governRequest is the client → server message for a tool call.
type governRequest struct {
	Type               string              `json:"type"`
	CallID             string              `json:"call_id"`
	AgentID            string              `json:"agent_id"`
	SessionID          string              `json:"session_id"`
	ToolID             string              `json:"tool_id"`
	Args               map[string]any      `json:"args"`
	PrincipalToken     string              `json:"principal_token,omitempty"`
	ExecutionTimeoutMs int                 `json:"execution_timeout_ms,omitempty"`
	Model              *core.ModelIdentity `json:"model,omitempty"`
	ModelName          string              `json:"model_name,omitempty"`
	ModelFingerprint   string              `json:"model_fingerprint,omitempty"`
	ModelProvider      string              `json:"model_provider,omitempty"`
	ModelVersion       string              `json:"model_version,omitempty"`
}

type governJSONRPCParams struct {
	CallID             string              `json:"call_id"`
	AgentID            string              `json:"agent_id"`
	SessionID          string              `json:"session_id"`
	ToolID             string              `json:"tool_id"`
	Tool               string              `json:"tool"`
	Operation          string              `json:"operation"`
	Args               map[string]any      `json:"args"`
	PrincipalToken     string              `json:"principal_token,omitempty"`
	ExecutionTimeoutMs int                 `json:"execution_timeout_ms,omitempty"`
	Model              *core.ModelIdentity `json:"model,omitempty"`
	ModelName          string              `json:"model_name,omitempty"`
	ModelFingerprint   string              `json:"model_fingerprint,omitempty"`
	ModelProvider      string              `json:"model_provider,omitempty"`
	ModelVersion       string              `json:"model_version,omitempty"`
}

// governResponse is the server → client message for a decision.
type governResponse struct {
	CallID         string `json:"call_id"`
	Effect         string `json:"effect"`
	DenialToken    string `json:"denial_token,omitempty"`
	RetryPermitted bool   `json:"retry_permitted,omitempty"`
	DeferToken     string `json:"defer_token,omitempty"`
	LatencyMs      int64  `json:"latency_ms"`
}

type auditEvent struct {
	Decision        core.Decision
	AgentID         string
	SessionID       string
	ToolID          string
	ToolName        string
	Operation       string
	Reason          string
	Args            map[string]any
	PrincipalID     string
	PrincipalMethod string
	BlastRadius     string
	Reversibility   string
}

type callbackEvent struct {
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`

	// Decision lifecycle payload.
	CallID           string         `json:"call_id,omitempty"`
	AgentID          string         `json:"agent_id,omitempty"`
	SessionID        string         `json:"session_id,omitempty"`
	ToolID           string         `json:"tool_id,omitempty"`
	Effect           string         `json:"effect,omitempty"`
	RuleID           string         `json:"rule_id,omitempty"`
	ReasonCode       string         `json:"reason_code,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	RecordID         string         `json:"record_id,omitempty"`
	LatencyMs        int64          `json:"latency_ms,omitempty"`
	DeferToken       string         `json:"defer_token,omitempty"`
	ToolName         string         `json:"tool_name,omitempty"`
	Operation        string         `json:"operation,omitempty"`
	BlastRadius      string         `json:"blast_radius,omitempty"`
	Reversibility    string         `json:"reversibility,omitempty"`
	PolicyVersion    string         `json:"policy_version,omitempty"`
	IncidentCategory string         `json:"incident_category,omitempty"`
	IncidentSeverity string         `json:"incident_severity,omitempty"`
	PrincipalID      string         `json:"principal_id,omitempty"`
	PrincipalMethod  string         `json:"principal_method,omitempty"`
	Args             map[string]any `json:"args,omitempty"`

	// Defer resolution payload.
	Status     string `json:"status,omitempty"`
	Approved   *bool  `json:"approved,omitempty"`
	ApproverID string `json:"approver_id,omitempty"`
}

// pollDeferRequest is the client → server message for polling a DEFER.
type pollDeferRequest struct {
	Type       string `json:"type"`
	AgentID    string `json:"agent_id"`
	DeferToken string `json:"defer_token"`
}

// pollDeferResponse is the server → client message for a DEFER poll.
type pollDeferResponse struct {
	DeferToken string `json:"defer_token"`
	Status     string `json:"status"`
}

// approveRequest is the client → server message for approving/denying a DEFER.
type approveRequest struct {
	Type       string `json:"type"`
	DeferToken string `json:"defer_token"`
	Approved   bool   `json:"approved"`
	ApproverID string `json:"approver_id,omitempty"`
	Reason     string `json:"reason"`
}

// scanOutputRequest is sent after the client executes a PERMIT'd tool; the server
// applies post_rules and returns sanitized output or a denial signal.
type scanOutputRequest struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id"`
	ToolID  string `json:"tool_id"`
	Output  string `json:"output"`
}

type scanOutputResponse struct {
	Outcome         string `json:"outcome"`
	SanitizedOutput string `json:"sanitized_output,omitempty"`
	ReasonCode      string `json:"reason_code,omitempty"`
	Reason          string `json:"reason,omitempty"`
	DeferToken      string `json:"defer_token,omitempty"`
}

type governOutputRequest struct {
	Type           string   `json:"type"`
	AgentID        string   `json:"agent_id"`
	SessionID      string   `json:"session_id,omitempty"`
	OutputType     string   `json:"output_type,omitempty"`
	Output         string   `json:"output"`
	SourceAgentIDs []string `json:"source_agent_ids,omitempty"`
}

type statusResponse struct {
	Running        bool   `json:"running"`
	PolicyLoaded   bool   `json:"policy_loaded"`
	PolicyVersion  string `json:"policy_version,omitempty"`
	DPRHealthy     bool   `json:"dpr_healthy"`
	ActiveSessions int    `json:"active_sessions"`
	TrustLevel     string `json:"trust_level,omitempty"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
}

type sessionRequest struct {
	Type    string `json:"type"`
	Op      string `json:"op"`
	AgentID string `json:"agent_id,omitempty"`
	Budget  int    `json:"budget,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	Counter string `json:"counter,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

type managedSession struct {
	AgentID   string   `json:"agent_id"`
	Open      bool     `json:"open"`
	Budget    int      `json:"budget,omitempty"`
	TTL       string   `json:"ttl,omitempty"`
	Purposes  []string `json:"purposes,omitempty"`
	OpenedAt  string   `json:"opened_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

type modelRequest struct {
	Type        string `json:"type"`
	Op          string `json:"op"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Version     string `json:"version,omitempty"`
	Agent       string `json:"agent,omitempty"`
	Window      string `json:"window,omitempty"`
}

type modelRecord struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Version     string `json:"version,omitempty"`
	Registered  string `json:"registered_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type provenanceRequest struct {
	Type       string `json:"type"`
	Op         string `json:"op"`
	AgentID    string `json:"agent_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Framework  string `json:"framework,omitempty"`
	Tools      string `json:"tools,omitempty"`
	SigningKey string `json:"signing_key,omitempty"`
}

type provenanceRecord struct {
	RecordID    string `json:"record_id"`
	AgentID     string `json:"agent_id"`
	Model       string `json:"model,omitempty"`
	Framework   string `json:"framework,omitempty"`
	Tools       string `json:"tools,omitempty"`
	SigningKey  string `json:"signing_key,omitempty"`
	CreatedAt   string `json:"created_at"`
	Verified    bool   `json:"verified"`
	TrustStatus string `json:"trust_status"`
}

type identityRequest struct {
	Type     string `json:"type"`
	Op       string `json:"op"`
	SPIFFEID string `json:"spiffe_id,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Bundle   string `json:"bundle,omitempty"`
	Workload string `json:"workload,omitempty"`
	IDP      string `json:"idp,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type identityFederation struct {
	IDP       string `json:"idp"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	CreatedAt string `json:"created_at"`
}

type identityState struct {
	SPIFFEID           string
	Domain             string
	Bundle             string
	Workload           string
	TrustLevel         string
	VerificationMethod string
	Federations        map[string]identityFederation
}

type credentialRequest struct {
	Type      string `json:"type"`
	Op        string `json:"op"`
	Name      string `json:"name,omitempty"`
	Key       string `json:"key,omitempty"`
	Scope     string `json:"scope,omitempty"`
	MaxScope  string `json:"max_scope,omitempty"`
	Window    string `json:"window,omitempty"`
	ToolID    string `json:"tool_id,omitempty"`
	Operation string `json:"operation,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	HandleID  string `json:"handle_id,omitempty"`
	Required  *bool  `json:"required,omitempty"`
}

type credentialRecord struct {
	Name      string   `json:"name"`
	Key       string   `json:"key,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	MaxScope  string   `json:"max_scope,omitempty"`
	Status    string   `json:"status"`
	Audit     []string `json:"audit,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type credentialLease struct {
	Handle *credential.CredentialHandle
}

type incidentRequest struct {
	Type       string `json:"type"`
	Op         string `json:"op"`
	ID         string `json:"id,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
	Agent      string `json:"agent,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type incidentRecord struct {
	ID         string   `json:"id"`
	AgentID    string   `json:"agent_id"`
	Severity   string   `json:"severity"`
	Reason     string   `json:"reason"`
	Status     string   `json:"status"`
	Evidence   []string `json:"evidence,omitempty"`
	CreatedAt  string   `json:"created_at"`
	ResolvedAt string   `json:"resolved_at,omitempty"`
}

type compensateRequest struct {
	Type     string `json:"type"`
	Op       string `json:"op"`
	ID       string `json:"id,omitempty"`
	Agent    string `json:"agent,omitempty"`
	FromStep string `json:"from_step,omitempty"`
}

type agentRequest struct {
	Type       string `json:"type"`
	Op         string `json:"op"`
	Agent      string `json:"agent,omitempty"`
	ID         string `json:"id,omitempty"`
	Window     string `json:"window,omitempty"`
	AdminToken string `json:"admin_token,omitempty"`
}

type compensateRecord struct {
	ID        string `json:"id"`
	Agent     string `json:"agent,omitempty"`
	Status    string `json:"status"`
	FromStep  string `json:"from_step,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

// Server listens on a Unix socket and serves governance requests.
type Server struct {
	pipeline          *core.Pipeline
	log               *zap.Logger
	principalResolver func(context.Context, string) (*principal.Identity, error)
	listenerMu        sync.Mutex
	listener          net.Listener
	acceptDone        chan struct{}
	started           time.Time
	sessMu            sync.RWMutex
	sessions          map[string]*managedSession
	modelMu           sync.RWMutex
	models            map[string]*modelRecord
	provMu            sync.RWMutex
	provByAgent       map[string]*provenanceRecord
	identityMu        sync.RWMutex
	identity          identityState
	credMu            sync.RWMutex
	credentials       map[string]*credentialRecord
	leaseMu           sync.Mutex
	credentialLeases  map[string]*credentialLease
	incidentMu        sync.RWMutex
	incidents         map[string]*incidentRecord
	incidentCounter   int
	compMu            sync.RWMutex
	compensations     map[string]*compensateRecord
	// subscribers receive copies of every decision for audit tail.
	subsMu     sync.Mutex
	subs       []chan auditEvent
	cbSubs     []chan callbackEvent
	wg         sync.WaitGroup
	rlMu       sync.Mutex
	rl         map[string]*rate.Limiter
	connTokens chan struct{}
	// standingAdminToken, when non-empty, requires matching "admin_token" on
	// standing_grant_* JSON requests (constant-time compare). When empty,
	// standing grant APIs are disabled (fail closed).
	standingAdminToken string
	shutdownFunc       func()
	delegate           *delegate.Service
}

// NewServer creates a new SDK socket server.
func NewServer(pipeline *core.Pipeline, log *zap.Logger) *Server {
	return &Server{
		pipeline:    pipeline,
		log:         log,
		started:     time.Now(),
		sessions:    make(map[string]*managedSession),
		models:      make(map[string]*modelRecord),
		provByAgent: make(map[string]*provenanceRecord),
		identity: identityState{
			TrustLevel:         "unknown",
			VerificationMethod: "unknown",
			Federations:        make(map[string]identityFederation),
		},
		credentials:      make(map[string]*credentialRecord),
		credentialLeases: make(map[string]*credentialLease),
		incidents:        make(map[string]*incidentRecord),
		compensations:    make(map[string]*compensateRecord),
		rl:               make(map[string]*rate.Limiter),
		connTokens:       make(chan struct{}, 256),
	}
}

// SetPrincipalResolver wires bearer-token principal verification into govern requests.
func (s *Server) SetPrincipalResolver(resolver func(context.Context, string) (*principal.Identity, error)) {
	s.principalResolver = resolver
}

// SetStandingAdminToken configures authentication for standing_grant_add|revoke|list.
// When non-empty, each request must include "admin_token" with the same value.
// When empty, standing grant operations are rejected (operators must set
// --standing-admin-token or share --policy-admin-token via daemon flags / env).
func (s *Server) SetStandingAdminToken(token string) {
	s.standingAdminToken = strings.TrimSpace(token)
}

// SetShutdownFunc configures the callback used by socket shutdown requests.
// SetDelegateService injects the delegation grant service used by the
// "delegate" socket dispatch. When unset, delegate requests fail closed.
func (s *Server) SetDelegateService(svc *delegate.Service) {
	s.delegate = svc
}

func (s *Server) SetShutdownFunc(fn func()) {
	s.shutdownFunc = fn
}

// Listen binds the Unix socket and starts accepting connections.
func (s *Server) Listen(socketPath string) error {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		if !isAddrInUseError(err) {
			return fmt.Errorf("listen on %q: %w", socketPath, err)
		}

		if err := validateSocketPathForReuse(socketPath); err != nil {
			return err
		}

		active, probeErr := unixSocketAcceptingConnections(socketPath, 300*time.Millisecond)
		if probeErr != nil {
			return fmt.Errorf("probe existing socket %q: %w", socketPath, probeErr)
		}
		if active {
			return fmt.Errorf("socket %q is already in use by another daemon", socketPath)
		}

		if rmErr := os.Remove(socketPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("remove stale socket: %w", rmErr)
		}

		ln, err = net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("listen on %q: %w", socketPath, err)
		}
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.listenerMu.Lock()
	s.listener = ln
	s.acceptDone = make(chan struct{})
	acceptDone := s.acceptDone
	s.listenerMu.Unlock()
	s.log.Info("SDK adapter listening", zap.String("socket", socketPath))
	go s.accept(ln, acceptDone)
	return nil
}

func validateSocketPathForReuse(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket path %q: %w", socketPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path %q exists and is not a Unix socket", socketPath)
	}
	return nil
}

func unixSocketAcceptingConnections(socketPath string, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return false, nil
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return false, fmt.Errorf("socket exists but is not accessible: %w", err)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// A timeout indicates a potentially active but overloaded endpoint; fail closed.
		return true, nil
	}
	return false, err
}

func isAddrInUseError(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.EADDRINUSE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

// Subscribe returns a channel that receives a copy of every Decision.
// Used by audit tail.
func (s *Server) Subscribe() chan auditEvent {
	ch := make(chan auditEvent, 64)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()
	return ch
}

// SubscribeCallbacks returns a channel that receives SDK callback events.
func (s *Server) SubscribeCallbacks() chan callbackEvent {
	ch := make(chan callbackEvent, 64)
	s.subsMu.Lock()
	s.cbSubs = append(s.cbSubs, ch)
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel.
func (s *Server) Unsubscribe(ch chan auditEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for i, sub := range s.subs {
		if sub == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// UnsubscribeCallbacks removes a callback subscription channel.
func (s *Server) UnsubscribeCallbacks(ch chan callbackEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for i, sub := range s.cbSubs {
		if sub == ch {
			s.cbSubs = append(s.cbSubs[:i], s.cbSubs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Close shuts down the listener.
func (s *Server) Close() error {
	var closeErr error

	s.listenerMu.Lock()
	ln := s.listener
	acceptDone := s.acceptDone
	s.listener = nil
	s.acceptDone = nil
	s.listenerMu.Unlock()

	if ln != nil {
		closeErr = ln.Close()
	}

	if acceptDone != nil {
		select {
		case <-acceptDone:
		case <-time.After(5 * time.Second):
			s.log.Warn("SDK adapter accept loop drain timeout reached; waiting on handlers anyway")
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.log.Warn("SDK adapter graceful drain timeout reached; closing anyway")
	}

	s.releaseCredentialLeases()
	return closeErr
}

func (s *Server) releaseCredentialLeases() {
	s.leaseMu.Lock()
	leases := s.credentialLeases
	s.credentialLeases = make(map[string]*credentialLease)
	s.leaseMu.Unlock()

	if len(leases) == 0 {
		return
	}

	const (
		leaseReleaseTimeout = 2 * time.Second
		leaseDrainTimeout   = 5 * time.Second
	)

	var wg sync.WaitGroup
	for handleID, lease := range leases {
		if lease == nil || lease.Handle == nil {
			continue
		}
		wg.Add(1)
		go func(id string, handle *credential.CredentialHandle) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
			defer cancel()
			if err := handle.Release(ctx); err != nil {
				s.log.Warn("credential lease release failed during shutdown",
					zap.String("handle_id", id),
					zap.Error(err),
				)
			}
		}(handleID, lease.Handle)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(leaseDrainTimeout):
		s.log.Warn("credential lease drain timeout reached; continuing shutdown")
	}
}

func (s *Server) accept(ln net.Listener, acceptDone chan struct{}) {
	if acceptDone != nil {
		defer close(acceptDone)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		logPeerCredentials(s.log, conn)
		select {
		case s.connTokens <- struct{}{}:
		default:
			_ = conn.Close()
			s.log.Warn("SDK adapter connection limit reached; dropping connection")
			continue
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.connTokens }()
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			writeJSON(conn, map[string]any{"error": "invalid JSON"})
			continue
		}

		var msgType string
		if raw, ok := msg["type"]; ok {
			_ = json.Unmarshal(raw, &msgType)
		}
		var method string
		if raw, ok := msg["method"]; ok {
			_ = json.Unmarshal(raw, &method)
		}

		if msgType == "" && method == "govern" {
			s.handleGovernJSONRPC(conn, msg)
			continue
		}

		switch msgType {
		case "govern", "":
			s.handleGovern(conn, line)
		case "status":
			s.handleStatus(conn)
		case "session":
			s.handleSession(conn, line)
		case "model":
			s.handleModel(conn, line)
		case "provenance":
			s.handleProvenance(conn, line)
		case "identity":
			s.handleIdentity(conn, line)
		case "credential":
			s.handleCredential(conn, line)
		case "incident":
			s.handleIncident(conn, line)
		case "compensate":
			s.handleCompensate(conn, line)
		case "delegate":
			s.handleDelegate(conn, line)
		case "poll_defer":
			s.handlePollDefer(conn, line)
		case "approve_defer":
			s.handleApproveDefer(conn, line)
		case "standing_grant_add":
			s.handleStandingGrantAdd(conn, line)
		case "standing_grant_revoke":
			s.handleStandingGrantRevoke(conn, line)
		case "standing_grant_list":
			s.handleStandingGrantList(conn, line)
		case "kill":
			s.handleKill(conn, line)
		case "agent":
			s.handleAgent(conn, line)
		case "shutdown":
			s.handleShutdown(conn, line)
		case "scan_output":
			s.handleScanOutput(conn, line)
		case "govern_output":
			s.handleGovernOutput(conn, line)
		case "audit_subscribe":
			// This call blocks — it streams decisions until the connection closes.
			s.handleAuditSubscribe(conn)
			return
		case "callback_subscribe":
			// This call blocks — it streams callback events until the connection closes.
			s.handleCallbackSubscribe(conn)
			return
		default:
			writeJSON(conn, map[string]any{"error": "unknown type: " + msgType})
		}
	}
}

func (s *Server) resolveGovernRequest(req governRequest) (governResponse, core.Decision, *principal.Identity, error) {
	if req.AgentID != "" && !s.allowAgent(req.AgentID) {
		return governResponse{}, core.Decision{}, nil, fmt.Errorf("rate_limited")
	}
	if req.CallID == "" {
		req.CallID = uuid.New().String()
	}
	resolvedPrincipal := s.resolvePrincipalFromToken(req.AgentID, req.PrincipalToken)
	if strings.TrimSpace(req.PrincipalToken) != "" && (resolvedPrincipal == nil || !resolvedPrincipal.Verified) {
		decision := core.Decision{
			Effect:     core.EffectDeny,
			ReasonCode: reasons.PrincipalVerificationUntrusted,
			Reason:     "principal token could not be verified",
		}
		return governResponse{
			CallID:    req.CallID,
			Effect:    string(decision.Effect),
			LatencyMs: 0,
		}, decision, resolvedPrincipal, nil
	}

	car := core.CanonicalActionRequest{
		CallID:             req.CallID,
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ToolID:             req.ToolID,
		Args:               req.Args,
		Principal:          resolvedPrincipal,
		ExecutionTimeoutMS: req.ExecutionTimeoutMs,
		Model:              modelIdentityFromRequest(req.Model, req.ModelName, req.ModelFingerprint, req.ModelProvider, req.ModelVersion),
		Timestamp:          time.Now(),
		InterceptAdapter:   "sdk",
	}

	decision := s.pipeline.Evaluate(car)
	resp := governResponse{
		CallID:         req.CallID,
		Effect:         string(decision.Effect),
		DenialToken:    decision.DenialToken,
		RetryPermitted: decision.RetryPermitted,
		DeferToken:     decision.DeferToken,
		LatencyMs:      decision.Latency.Milliseconds(),
	}
	return resp, decision, resolvedPrincipal, nil
}

func splitToolID(toolID string) (string, string) {
	clean := strings.TrimSpace(toolID)
	if clean == "" {
		return "", ""
	}
	parts := strings.Split(clean, "/")
	if len(parts) < 2 {
		return clean, "invoke"
	}
	operation := strings.TrimSpace(parts[len(parts)-1])
	tool := strings.TrimSpace(strings.Join(parts[:len(parts)-1], "/"))
	if tool == "" {
		tool = clean
	}
	if operation == "" {
		operation = "invoke"
	}
	return tool, operation
}

func modelIdentityFromRequest(direct *core.ModelIdentity, name, fingerprint, provider, version string) *core.ModelIdentity {
	if direct != nil {
		m := &core.ModelIdentity{
			Name:        strings.TrimSpace(direct.Name),
			Fingerprint: strings.ToLower(strings.TrimSpace(direct.Fingerprint)),
			Provider:    strings.ToLower(strings.TrimSpace(direct.Provider)),
			Version:     strings.TrimSpace(direct.Version),
		}
		if m.Name != "" || m.Fingerprint != "" || m.Provider != "" || m.Version != "" {
			return m
		}
	}

	m := &core.ModelIdentity{
		Name:        strings.TrimSpace(name),
		Fingerprint: strings.ToLower(strings.TrimSpace(fingerprint)),
		Provider:    strings.ToLower(strings.TrimSpace(provider)),
		Version:     strings.TrimSpace(version),
	}
	if m.Name == "" && m.Fingerprint == "" && m.Provider == "" && m.Version == "" {
		return nil
	}
	return m
}

func (s *Server) resolvePrincipalFromToken(agentID, principalToken string) *principal.Identity {
	token := strings.TrimSpace(principalToken)
	if token == "" {
		return nil
	}
	if s.principalResolver == nil {
		s.log.Warn("principal token provided but no idp resolver is configured",
			zap.String("agent_id", agentID),
		)
		return &principal.Identity{ID: "idp:unverified", Verified: false, Method: "idp_untrusted"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resolved, err := s.principalResolver(ctx, token)
	if err != nil {
		s.log.Warn("principal token verification failed",
			zap.String("agent_id", agentID),
			zap.Error(err),
		)
		return &principal.Identity{ID: "idp:unverified", Verified: false, Method: "idp_untrusted"}
	}
	if resolved == nil || strings.TrimSpace(resolved.ID) == "" || !resolved.Verified {
		s.log.Warn("principal token resolver returned invalid identity",
			zap.String("agent_id", agentID),
		)
		return &principal.Identity{ID: "idp:unverified", Verified: false, Method: "idp_untrusted"}
	}
	return resolved
}

func (s *Server) emitGovernDecision(req governRequest, decision core.Decision, resolvedPrincipal *principal.Identity) {
	toolName, operation := splitToolID(req.ToolID)
	toolMeta := core.ToolRuntimeMeta{}
	if s.pipeline != nil {
		toolMeta = s.pipeline.ToolMetadata(req.ToolID)
	}
	principalID := ""
	principalMethod := ""
	if resolvedPrincipal != nil {
		principalID = strings.TrimSpace(resolvedPrincipal.ID)
		principalMethod = strings.TrimSpace(resolvedPrincipal.Method)
	}

	s.broadcast(auditEvent{
		Decision:        decision,
		AgentID:         req.AgentID,
		SessionID:       req.SessionID,
		ToolID:          req.ToolID,
		ToolName:        toolName,
		Operation:       operation,
		Reason:          decision.Reason,
		Args:            req.Args,
		PrincipalID:     principalID,
		PrincipalMethod: principalMethod,
		BlastRadius:     toolMeta.BlastRadius,
		Reversibility:   toolMeta.Reversibility,
	})
	s.broadcastCallback(callbackEvent{
		EventType:        "decision",
		Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
		CallID:           req.CallID,
		AgentID:          req.AgentID,
		SessionID:        req.SessionID,
		ToolID:           req.ToolID,
		ToolName:         toolName,
		Operation:        operation,
		Effect:           string(decision.Effect),
		RuleID:           decision.RuleID,
		ReasonCode:       reasons.Normalize(decision.ReasonCode),
		Reason:           decision.Reason,
		RecordID:         decision.DPRRecordID,
		LatencyMs:        decision.Latency.Milliseconds(),
		DeferToken:       decision.DeferToken,
		BlastRadius:      toolMeta.BlastRadius,
		Reversibility:    toolMeta.Reversibility,
		PolicyVersion:    decision.PolicyVersion,
		IncidentCategory: decision.IncidentCategory,
		IncidentSeverity: decision.IncidentSeverity,
		PrincipalID:      principalID,
		PrincipalMethod:  principalMethod,
		Args:             req.Args,
	})

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "governed", observe.EventGovernDecision,
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.String("agent_id", req.AgentID),
		zap.String("session_id", req.SessionID),
		zap.String("call_id", req.CallID),
		zap.String("tool_id", req.ToolID),
		zap.String("effect", string(decision.Effect)),
		zap.String("reason_code", reasons.Normalize(decision.ReasonCode)),
		zap.String("rule_id", decision.RuleID),
		zap.String("policy_version", decision.PolicyVersion),
		zap.Int64("latency_ms", decision.Latency.Milliseconds()),
		zap.Duration("latency", decision.Latency),
	)
}

func (s *Server) handleGovernJSONRPC(conn net.Conn, msg map[string]json.RawMessage) {
	var id any
	if rawID, ok := msg["id"]; ok {
		_ = json.Unmarshal(rawID, &id)
	}
	var p governJSONRPCParams
	if rawParams, ok := msg["params"]; ok {
		if err := json.Unmarshal(rawParams, &p); err != nil {
			writeJSON(conn, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32602, "message": "invalid params"}})
			return
		}
	}
	toolID := strings.TrimSpace(p.ToolID)
	if toolID == "" && strings.TrimSpace(p.Tool) != "" {
		op := strings.TrimSpace(p.Operation)
		if op == "" {
			op = "invoke"
		}
		toolID = strings.TrimSpace(p.Tool) + "/" + op
	}
	req := governRequest{
		Type:               "govern",
		CallID:             p.CallID,
		AgentID:            p.AgentID,
		SessionID:          p.SessionID,
		ToolID:             toolID,
		Args:               p.Args,
		PrincipalToken:     p.PrincipalToken,
		ExecutionTimeoutMs: p.ExecutionTimeoutMs,
		Model:              p.Model,
		ModelName:          p.ModelName,
		ModelFingerprint:   p.ModelFingerprint,
		ModelProvider:      p.ModelProvider,
		ModelVersion:       p.ModelVersion,
	}
	resp, decision, resolvedPrincipal, err := s.resolveGovernRequest(req)
	if err != nil {
		code := -32000
		msg := err.Error()
		if msg == "rate_limited" {
			msg = "rate_limited"
		}
		writeJSON(conn, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
		return
	}
	req.CallID = resp.CallID
	writeJSON(conn, map[string]any{"jsonrpc": "2.0", "id": id, "result": resp})
	s.emitGovernDecision(req, decision, resolvedPrincipal)
}

func (s *Server) handleStatus(conn net.Conn) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	snap := s.pipeline.StatusSnapshot()
	uptime := int64(time.Since(s.started).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	writeJSON(conn, statusResponse{
		Running:        true,
		PolicyLoaded:   snap.PolicyLoaded,
		PolicyVersion:  snap.PolicyVersion,
		DPRHealthy:     snap.DPRHealthy,
		ActiveSessions: snap.ActiveSessions,
		TrustLevel:     snap.TrustLevel,
		UptimeSeconds:  uptime,
	})
}

func (s *Server) handleSession(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}

	var req sessionRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid session request"})
		return
	}

	agentID := req.AgentID
	if req.Op != "list" && strings.TrimSpace(agentID) == "" {
		writeJSON(conn, map[string]any{"error": "agent_id is required"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	sess := s.sessions[agentID]
	ensureSess := func() *managedSession {
		if sess == nil {
			sess = &managedSession{AgentID: agentID}
			s.sessions[agentID] = sess
		}
		return sess
	}

	switch req.Op {
	case "open":
		ms := ensureSess()
		ms.Open = true
		if req.Budget > 0 {
			ms.Budget = req.Budget
		}
		if strings.TrimSpace(req.TTL) != "" {
			ms.TTL = req.TTL
		}
		if ms.OpenedAt == "" {
			ms.OpenedAt = now
		}
		ms.UpdatedAt = now
		_ = s.pipeline.SessionManager().Get(agentID)
		writeJSON(conn, ms)

	case "close":
		if sess == nil {
			writeJSON(conn, map[string]any{"agent_id": agentID, "open": false})
			return
		}
		sess.Open = false
		sess.UpdatedAt = now
		writeJSON(conn, sess)

	case "list":
		out := make([]*managedSession, 0, len(s.sessions))
		for _, v := range s.sessions {
			if strings.TrimSpace(req.AgentID) != "" && v.AgentID != req.AgentID {
				continue
			}
			copy := *v
			out = append(out, &copy)
		}
		writeJSON(conn, map[string]any{"sessions": out})

	case "budget_get":
		if sess == nil {
			writeJSON(conn, map[string]any{"agent_id": agentID, "budget": 0})
			return
		}
		writeJSON(conn, map[string]any{"agent_id": agentID, "budget": sess.Budget})

	case "budget_set":
		ms := ensureSess()
		ms.Budget = req.Budget
		ms.UpdatedAt = now
		writeJSON(conn, map[string]any{"agent_id": agentID, "budget": ms.Budget})

	case "reset":
		s.pipeline.SessionManager().Reset(agentID, req.Counter)
		if sess != nil {
			sess.UpdatedAt = now
		}
		writeJSON(conn, map[string]any{"ok": true, "agent_id": agentID, "counter": req.Counter})

	case "inspect":
		state := s.pipeline.SessionManager().Get(agentID)
		history := state.History()
		ms := ensureSess()
		writeJSON(conn, map[string]any{
			"agent_id":      agentID,
			"open":          ms.Open,
			"budget":        ms.Budget,
			"ttl":           ms.TTL,
			"purposes":      ms.Purposes,
			"opened_at":     ms.OpenedAt,
			"updated_at":    ms.UpdatedAt,
			"call_count":    state.CallCount(),
			"session_cost":  state.CurrentCostUSD(),
			"daily_cost":    state.DailyCostUSD(),
			"history":       history,
			"history_count": len(history),
			"killed":        state.IsKilled(),
			"phase":         state.CurrentPhase(),
		})

	case "purpose_declare":
		if strings.TrimSpace(req.Purpose) == "" {
			writeJSON(conn, map[string]any{"error": "purpose is required"})
			return
		}
		ms := ensureSess()
		ms.Purposes = append(ms.Purposes, req.Purpose)
		ms.UpdatedAt = now
		writeJSON(conn, map[string]any{"agent_id": agentID, "purposes": ms.Purposes})

	case "purpose_list":
		if sess == nil {
			writeJSON(conn, map[string]any{"agent_id": agentID, "purposes": []string{}})
			return
		}
		writeJSON(conn, map[string]any{"agent_id": agentID, "purposes": sess.Purposes})

	default:
		writeJSON(conn, map[string]any{"error": "unknown session op: " + req.Op})
	}
}

func (s *Server) handleModel(conn net.Conn, line []byte) {
	var req modelRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid model request"})
		return
	}
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}

	switch req.Op {
	case "register":
		if strings.TrimSpace(req.Name) == "" {
			writeJSON(conn, map[string]any{"error": "name is required"})
			return
		}
		rec := s.pipeline.RegisterModelIdentity(req.Name, req.Fingerprint, req.Provider, req.Version)
		writeJSON(conn, map[string]any{"ok": true, "model": rec})

	case "verify":
		result := s.pipeline.VerifyModelIdentity(req.Agent, modelIdentityFromRequest(nil, req.Name, req.Fingerprint, req.Provider, req.Version))
		writeJSON(conn, map[string]any{
			"verified":         result.Verified,
			"required":         result.Required,
			"strict":           result.Strict,
			"reason":           result.Reason,
			"agent":            req.Agent,
			"registered_count": result.RegisteredCount,
			"declared":         result.Declared,
			"presented":        result.Presented,
			"registered":       result.Registered,
		})

	case "consistency":
		status := "consistent"
		registered := s.pipeline.ListModelIdentities()
		if len(registered) == 0 {
			status = "unknown"
		}
		writeJSON(conn, map[string]any{
			"status":            status,
			"agent":             req.Agent,
			"window":            req.Window,
			"registered_models": len(registered),
		})

	case "list":
		writeJSON(conn, map[string]any{"models": s.pipeline.ListModelIdentities()})

	case "alert":
		result := s.pipeline.VerifyModelIdentity(req.Agent, nil)
		alerts := []string{}
		if result.Required && !result.Verified {
			alerts = append(alerts, result.Reason)
		}
		writeJSON(conn, map[string]any{
			"agent":  req.Agent,
			"alerts": alerts,
		})

	default:
		writeJSON(conn, map[string]any{"error": "unknown model op: " + req.Op})
	}
}

func (s *Server) handleProvenance(conn net.Conn, line []byte) {
	var req provenanceRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid provenance request"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.provMu.Lock()
	defer s.provMu.Unlock()

	switch req.Op {
	case "sign":
		if strings.TrimSpace(req.AgentID) == "" {
			writeJSON(conn, map[string]any{"error": "agent_id is required"})
			return
		}
		rec := &provenanceRecord{
			RecordID:    uuid.NewString(),
			AgentID:     req.AgentID,
			Model:       req.Model,
			Framework:   req.Framework,
			Tools:       req.Tools,
			SigningKey:  req.SigningKey,
			CreatedAt:   now,
			Verified:    true,
			TrustStatus: "trusted",
		}
		s.provByAgent[req.AgentID] = rec
		writeJSON(conn, rec)

	case "verify":
		rec := s.provByAgent[req.AgentID]
		if rec == nil {
			writeJSON(conn, map[string]any{"agent_id": req.AgentID, "verified": false, "status": "missing"})
			return
		}
		writeJSON(conn, map[string]any{"agent_id": req.AgentID, "verified": rec.Verified, "status": rec.TrustStatus, "record_id": rec.RecordID})

	case "inspect":
		rec := s.provByAgent[req.AgentID]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "provenance record not found"})
			return
		}
		writeJSON(conn, rec)

	case "diff":
		rec := s.provByAgent[req.AgentID]
		if rec == nil {
			writeJSON(conn, map[string]any{"agent_id": req.AgentID, "drift": "unknown", "changes": []string{}})
			return
		}
		writeJSON(conn, map[string]any{"agent_id": req.AgentID, "drift": "none", "changes": []string{}, "record_id": rec.RecordID})

	case "list":
		out := make([]*provenanceRecord, 0, len(s.provByAgent))
		for _, rec := range s.provByAgent {
			copy := *rec
			out = append(out, &copy)
		}
		writeJSON(conn, map[string]any{"records": out})

	default:
		writeJSON(conn, map[string]any{"error": "unknown provenance op: " + req.Op})
	}
}

func (s *Server) handleIdentity(conn net.Conn, line []byte) {
	var req identityRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid identity request"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.identityMu.Lock()
	defer s.identityMu.Unlock()

	switch req.Op {
	case "verify":
		spiffe := strings.TrimSpace(req.SPIFFEID)
		verified := spiffe != "" || strings.TrimSpace(s.identity.SPIFFEID) != ""
		if spiffe != "" {
			s.identity.SPIFFEID = spiffe
		}
		if verified {
			s.identity.TrustLevel = "high"
			s.identity.VerificationMethod = "client_asserted"
			s.log.Warn("sdk identity verify accepted client-asserted SPIFFE claim without transport attestation",
				zap.String("spiffe_id", s.identity.SPIFFEID),
				zap.String("verification_method", s.identity.VerificationMethod))
		}
		writeJSON(conn, map[string]any{
			"verified":            verified,
			"spiffe_id":           s.identity.SPIFFEID,
			"trust_level":         s.identity.TrustLevel,
			"verification_method": s.identity.VerificationMethod,
		})

	case "trust":
		if strings.TrimSpace(req.Domain) != "" {
			s.identity.Domain = req.Domain
		}
		if strings.TrimSpace(req.Bundle) != "" {
			s.identity.Bundle = req.Bundle
		}
		if s.identity.Domain != "" && s.identity.Bundle != "" {
			s.identity.TrustLevel = "high"
		} else if s.identity.Domain != "" || s.identity.Bundle != "" {
			s.identity.TrustLevel = "medium"
		}
		if s.identity.Domain != "" || s.identity.Bundle != "" {
			s.identity.VerificationMethod = "client_asserted"
			s.log.Warn("sdk identity trust accepted client-asserted trust material without transport attestation",
				zap.String("domain", s.identity.Domain),
				zap.String("verification_method", s.identity.VerificationMethod))
		}
		writeJSON(conn, map[string]any{
			"domain":              s.identity.Domain,
			"bundle":              s.identity.Bundle,
			"trust_level":         s.identity.TrustLevel,
			"verification_method": s.identity.VerificationMethod,
		})

	case "whoami":
		writeJSON(conn, map[string]any{
			"spiffe_id":           s.identity.SPIFFEID,
			"domain":              s.identity.Domain,
			"workload":            s.identity.Workload,
			"trust_level":         s.identity.TrustLevel,
			"verification_method": s.identity.VerificationMethod,
		})

	case "attest":
		if strings.TrimSpace(req.Workload) != "" {
			s.identity.Workload = req.Workload
		}
		if s.identity.Workload != "" {
			if s.identity.TrustLevel == "unknown" {
				s.identity.TrustLevel = "medium"
			}
			s.identity.VerificationMethod = "client_asserted"
			s.log.Warn("sdk identity attest accepted client-asserted workload claim without transport attestation",
				zap.String("workload", s.identity.Workload),
				zap.String("verification_method", s.identity.VerificationMethod))
		}
		writeJSON(conn, map[string]any{
			"workload":            s.identity.Workload,
			"attested":            s.identity.Workload != "",
			"trust_level":         s.identity.TrustLevel,
			"verification_method": s.identity.VerificationMethod,
		})

	case "federation_add":
		if strings.TrimSpace(req.IDP) == "" {
			writeJSON(conn, map[string]any{"error": "idp is required"})
			return
		}
		s.identity.Federations[req.IDP] = identityFederation{
			IDP:       req.IDP,
			ClientID:  req.ClientID,
			Scope:     req.Scope,
			CreatedAt: now,
		}
		writeJSON(conn, map[string]any{"ok": true, "idp": req.IDP})

	case "federation_list":
		out := make([]identityFederation, 0, len(s.identity.Federations))
		for _, fed := range s.identity.Federations {
			out = append(out, fed)
		}
		writeJSON(conn, map[string]any{"federations": out})

	case "federation_revoke":
		if strings.TrimSpace(req.IDP) == "" {
			writeJSON(conn, map[string]any{"error": "idp is required"})
			return
		}
		delete(s.identity.Federations, req.IDP)
		writeJSON(conn, map[string]any{"ok": true, "idp": req.IDP})

	case "trust_level":
		writeJSON(conn, map[string]any{"trust_level": s.identity.TrustLevel})

	default:
		writeJSON(conn, map[string]any{"error": "unknown identity op: " + req.Op})
	}
}

func (s *Server) handleCredential(conn net.Conn, line []byte) {
	var req credentialRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid credential request"})
		return
	}
	op := strings.ToLower(strings.TrimSpace(req.Op))

	if op == "routing_map" || op == "broker_map" {
		if s.pipeline == nil {
			writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
			return
		}
		writeJSON(conn, s.pipeline.CredentialBrokerDiagnostics())
		return
	}

	if op == "acquire" {
		s.handleCredentialAcquire(conn, req)
		return
	}

	if op == "release" {
		s.handleCredentialRelease(conn, req)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	s.credMu.Lock()
	defer s.credMu.Unlock()

	switch op {
	case "register":
		if strings.TrimSpace(req.Name) == "" {
			writeJSON(conn, map[string]any{"error": "name is required"})
			return
		}
		rec := s.credentials[req.Name]
		if rec == nil {
			rec = &credentialRecord{Name: req.Name, CreatedAt: now}
			s.credentials[req.Name] = rec
		}
		rec.Key = req.Key
		rec.Scope = req.Scope
		rec.MaxScope = req.MaxScope
		rec.Status = "active"
		rec.UpdatedAt = now
		rec.Audit = append(rec.Audit, "registered")
		writeJSON(conn, rec)

	case "list":
		out := make([]*credentialRecord, 0, len(s.credentials))
		for _, rec := range s.credentials {
			copy := *rec
			out = append(out, &copy)
		}
		writeJSON(conn, map[string]any{"credentials": out})

	case "inspect":
		rec := s.credentials[req.Name]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "credential not found"})
			return
		}
		writeJSON(conn, rec)

	case "rotate":
		rec := s.credentials[req.Name]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "credential not found"})
			return
		}
		rec.Key = req.Key
		rec.UpdatedAt = now
		rec.Audit = append(rec.Audit, "rotated")
		writeJSON(conn, rec)

	case "health":
		writeJSON(conn, map[string]any{"healthy": true, "backends": []map[string]string{{"name": "inmemory", "status": "ok"}}})

	case "revoke":
		rec := s.credentials[req.Name]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "credential not found"})
			return
		}
		rec.Status = "revoked"
		rec.UpdatedAt = now
		rec.Audit = append(rec.Audit, "revoked")
		writeJSON(conn, rec)

	case "audit":
		rec := s.credentials[req.Name]
		if rec == nil {
			writeJSON(conn, map[string]any{"name": req.Name, "window": req.Window, "events": []string{}})
			return
		}
		writeJSON(conn, map[string]any{"name": req.Name, "window": req.Window, "events": rec.Audit})

	default:
		writeJSON(conn, map[string]any{"error": "unknown credential op: " + req.Op})
	}
}

func credentialRequestRequired(req credentialRequest) bool {
	if req.Required == nil {
		return true
	}
	return *req.Required
}

func (s *Server) handleCredentialAcquire(conn net.Conn, req credentialRequest) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}

	toolID := strings.TrimSpace(req.ToolID)
	if toolID == "" {
		toolID = strings.TrimSpace(req.Name)
	}
	if toolID == "" {
		writeJSON(conn, map[string]any{"error": "tool_id is required"})
		return
	}

	required := credentialRequestRequired(req)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	handle, err := s.pipeline.AcquireCredentialHandle(ctx, credential.FetchRequest{
		ToolID:    toolID,
		Operation: strings.TrimSpace(req.Operation),
		Scope:     strings.TrimSpace(req.Scope),
		AgentID:   strings.TrimSpace(req.AgentID),
	}, required)
	if err != nil {
		writeJSON(conn, map[string]any{"error": "credential acquire failed: " + err.Error()})
		return
	}
	if handle == nil || handle.Credential == nil {
		writeJSON(conn, map[string]any{"ok": true, "brokered": false, "required": required})
		return
	}

	value := handle.Credential.Value
	if strings.TrimSpace(value) == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := handle.Release(ctx)
		cancel()
		if err != nil {
			s.log.Warn("credential acquire returned empty value and release failed",
				zap.String("tool_id", toolID),
				zap.Error(err),
			)
		}
		if required {
			writeJSON(conn, map[string]any{"error": "credential acquire returned empty value"})
			return
		}
		writeJSON(conn, map[string]any{"ok": true, "brokered": false, "required": required})
		return
	}

	handleID := "credh_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	s.leaseMu.Lock()
	s.credentialLeases[handleID] = &credentialLease{Handle: handle}
	s.leaseMu.Unlock()

	resp := map[string]any{
		"ok":        true,
		"brokered":  true,
		"required":  required,
		"handle_id": handleID,
		"value":     value,
		"source":    strings.TrimSpace(handle.Credential.Source),
		"scope":     strings.TrimSpace(handle.Credential.Scope),
	}
	if !handle.Credential.ExpiresAt.IsZero() {
		resp["expires_at"] = handle.Credential.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(conn, resp)
}

func (s *Server) handleCredentialRelease(conn net.Conn, req credentialRequest) {
	handleID := strings.TrimSpace(req.HandleID)
	if handleID == "" {
		writeJSON(conn, map[string]any{"error": "handle_id is required"})
		return
	}

	s.leaseMu.Lock()
	lease := s.credentialLeases[handleID]
	delete(s.credentialLeases, handleID)
	s.leaseMu.Unlock()

	if lease == nil || lease.Handle == nil {
		writeJSON(conn, map[string]any{"ok": true, "released": false, "handle_id": handleID})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lease.Handle.Release(ctx); err != nil {
		writeJSON(conn, map[string]any{"error": "credential release failed: " + err.Error()})
		return
	}

	writeJSON(conn, map[string]any{"ok": true, "released": true, "handle_id": handleID})
}

func (s *Server) handleIncident(conn net.Conn, line []byte) {
	var req incidentRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid incident request"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()

	switch req.Op {
	case "declare":
		agent := strings.TrimSpace(req.Agent)
		if agent == "" {
			agent = strings.TrimSpace(req.AgentID)
		}
		if agent == "" || strings.TrimSpace(req.Severity) == "" || strings.TrimSpace(req.Reason) == "" {
			writeJSON(conn, map[string]any{"error": "agent, severity, and reason are required"})
			return
		}
		s.incidentCounter++
		id := fmt.Sprintf("INC-%06d", s.incidentCounter)
		rec := &incidentRecord{
			ID:        id,
			AgentID:   agent,
			Severity:  req.Severity,
			Reason:    req.Reason,
			Status:    "open",
			Evidence:  []string{"dpr-chain", "policy-snapshot"},
			CreatedAt: now,
		}
		s.incidents[id] = rec
		writeJSON(conn, rec)

	case "list":
		out := make([]*incidentRecord, 0, len(s.incidents))
		for _, rec := range s.incidents {
			copy := *rec
			out = append(out, &copy)
		}
		writeJSON(conn, map[string]any{"incidents": out})

	case "inspect":
		rec := s.incidents[req.ID]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "incident not found"})
			return
		}
		writeJSON(conn, rec)

	case "isolate":
		agent := strings.TrimSpace(req.AgentID)
		if agent == "" {
			writeJSON(conn, map[string]any{"error": "agent_id is required"})
			return
		}
		updated := 0
		for _, rec := range s.incidents {
			if rec.AgentID == agent && rec.Status != "resolved" {
				rec.Status = "isolated"
				updated++
			}
		}
		writeJSON(conn, map[string]any{"agent_id": agent, "isolated_incidents": updated})

	case "evidence":
		rec := s.incidents[req.ID]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "incident not found"})
			return
		}
		writeJSON(conn, map[string]any{"id": req.ID, "evidence": rec.Evidence})

	case "resolve":
		id := strings.TrimSpace(req.IncidentID)
		if id == "" {
			id = strings.TrimSpace(req.ID)
		}
		rec := s.incidents[id]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "incident not found"})
			return
		}
		rec.Status = "resolved"
		rec.ResolvedAt = now
		writeJSON(conn, rec)

	case "playbook":
		rec := s.incidents[req.ID]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "incident not found"})
			return
		}
		steps := []string{"contain", "collect-evidence", "remediate", "postmortem"}
		if strings.EqualFold(rec.Severity, "critical") {
			steps = []string{"emergency-kill-switch", "contain", "collect-evidence", "exec-briefing", "remediate", "postmortem"}
		}
		writeJSON(conn, map[string]any{"id": rec.ID, "severity": rec.Severity, "steps": steps})

	default:
		writeJSON(conn, map[string]any{"error": "unknown incident op: " + req.Op})
	}
}

func (s *Server) handleCompensate(conn net.Conn, line []byte) {
	var req compensateRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid compensate request"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.compMu.Lock()
	defer s.compMu.Unlock()

	switch req.Op {
	case "list":
		out := make([]*compensateRecord, 0, len(s.compensations))
		for _, rec := range s.compensations {
			if strings.TrimSpace(req.Agent) != "" && rec.Agent != req.Agent {
				continue
			}
			copy := *rec
			out = append(out, &copy)
		}
		writeJSON(conn, map[string]any{"compensations": out})

	case "inspect":
		rec := s.compensations[req.ID]
		if rec == nil {
			writeJSON(conn, map[string]any{"error": "compensation not found"})
			return
		}
		writeJSON(conn, rec)

	case "apply":
		rec := s.compensations[req.ID]
		if rec == nil {
			rec = &compensateRecord{ID: req.ID, Status: "applied", UpdatedAt: now}
			s.compensations[req.ID] = rec
		} else {
			rec.Status = "applied"
			rec.UpdatedAt = now
		}
		writeJSON(conn, rec)

	case "status":
		rec := s.compensations[req.ID]
		if rec == nil {
			writeJSON(conn, map[string]any{"id": req.ID, "status": "unknown"})
			return
		}
		writeJSON(conn, map[string]any{"id": req.ID, "status": rec.Status, "updated_at": rec.UpdatedAt})

	case "retry":
		rec := s.compensations[req.ID]
		if rec == nil {
			rec = &compensateRecord{ID: req.ID}
			s.compensations[req.ID] = rec
		}
		rec.Status = "retrying"
		rec.FromStep = req.FromStep
		rec.UpdatedAt = now
		writeJSON(conn, rec)

	default:
		writeJSON(conn, map[string]any{"error": "unknown compensate op: " + req.Op})
	}
}

func (s *Server) handleGovern(conn net.Conn, line []byte) {
	var req governRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid govern request"})
		return
	}
	resp, decision, resolvedPrincipal, err := s.resolveGovernRequest(req)
	if err != nil {
		writeJSON(conn, map[string]any{"error": err.Error(), "reason_code": reasons.SessionRollingLimit})
		return
	}
	req.CallID = resp.CallID
	writeJSON(conn, resp)
	s.emitGovernDecision(req, decision, resolvedPrincipal)
}

func (s *Server) handlePollDefer(conn net.Conn, line []byte) {
	var req pollDeferRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid poll_defer request"})
		return
	}
	status, _ := s.pipeline.DeferWorkflow().Status(req.DeferToken)
	switch status {
	case "approved", "denied", "expired":
		var approved *bool
		switch status {
		case "approved":
			v := true
			approved = &v
		case "denied", "expired":
			v := false
			approved = &v
		}
		s.broadcastCallback(callbackEvent{
			EventType:  "defer_resolved",
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			AgentID:    req.AgentID,
			DeferToken: req.DeferToken,
			Status:     string(status),
			Approved:   approved,
		})
	}
	writeJSON(conn, pollDeferResponse{
		DeferToken: req.DeferToken,
		Status:     string(status),
	})
}

func (s *Server) handleApproveDefer(conn net.Conn, line []byte) {
	var req approveRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid approve_defer request"})
		return
	}
	reason := req.Reason
	if reason == "" {
		if req.Approved {
			reason = "approved via CLI"
		} else {
			reason = "denied via CLI"
		}
	}
	if err := s.pipeline.DeferWorkflow().Resolve(req.DeferToken, req.Approved, req.ApproverID, reason); err != nil {
		writeJSON(conn, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status := "denied"
	if req.Approved {
		status = "approved"
	}
	approved := req.Approved
	s.broadcastCallback(callbackEvent{
		EventType:  "defer_resolved",
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		DeferToken: req.DeferToken,
		Status:     status,
		Approved:   &approved,
		ApproverID: req.ApproverID,
		Reason:     reason,
	})
	writeJSON(conn, map[string]any{"ok": true})
}

func (s *Server) handleScanOutput(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	var req scanOutputRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid scan_output request"})
		return
	}
	if req.ToolID == "" {
		writeJSON(conn, map[string]any{"error": "tool_id is required"})
		return
	}
	if req.AgentID != "" && !s.allowAgent(req.AgentID) {
		writeJSON(conn, map[string]any{
			"error":       "rate_limited",
			"reason_code": reasons.SessionRollingLimit,
		})
		return
	}
	sr := s.pipeline.ScanOutput(req.ToolID, req.Output)
	writeJSON(conn, scanOutputResponse{
		Outcome:         string(sr.Outcome),
		SanitizedOutput: sr.Output,
		ReasonCode:      reasons.Normalize(sr.ReasonCode),
		Reason:          sr.Reason,
	})
}

func (s *Server) handleGovernOutput(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	var req governOutputRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid govern_output request"})
		return
	}
	if strings.TrimSpace(req.Output) == "" {
		writeJSON(conn, map[string]any{"error": "output is required"})
		return
	}
	if req.AgentID != "" && !s.allowAgent(req.AgentID) {
		writeJSON(conn, map[string]any{
			"error":       "rate_limited",
			"reason_code": reasons.SessionRollingLimit,
		})
		return
	}
	res := s.pipeline.GovernOutput(core.GovernOutputRequest{
		AgentID:        req.AgentID,
		SessionID:      req.SessionID,
		OutputType:     req.OutputType,
		Output:         req.Output,
		SourceAgentIDs: req.SourceAgentIDs,
	})
	writeJSON(conn, scanOutputResponse{
		Outcome:         res.Outcome,
		SanitizedOutput: res.SanitizedOutput,
		ReasonCode:      reasons.Normalize(res.ReasonCode),
		Reason:          res.Reason,
		DeferToken:      res.DeferToken,
	})
}

func (s *Server) handleKill(conn net.Conn, line []byte) {
	var req struct {
		AgentID    string `json:"agent_id"`
		AdminToken string `json:"admin_token,omitempty"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid kill request"})
		return
	}
	if !s.authorizeControlAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	if strings.TrimSpace(req.AgentID) == "" {
		writeJSON(conn, map[string]any{"error": "agent_id is required"})
		return
	}
	s.pipeline.SessionManager().Kill(req.AgentID)
	s.log.Warn("kill switch activated", zap.String("agent", req.AgentID))
	writeJSON(conn, map[string]any{"ok": true})
}

func (s *Server) handleAgent(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}

	var req agentRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid agent request"})
		return
	}

	op := strings.ToLower(strings.TrimSpace(req.Op))
	if op != "pending" {
		if !s.authorizeControlAdmin(conn, strings.TrimSpace(req.AdminToken)) {
			return
		}
	}

	sessionManager := s.pipeline.SessionManager()
	if sessionManager == nil {
		writeJSON(conn, map[string]any{"error": "session manager unavailable"})
		return
	}

	switch op {
	case "pending":
		pending := s.pipeline.DeferWorkflow().Pending()
		agentFilter := strings.TrimSpace(req.Agent)
		if agentFilter != "" {
			filtered := make([]map[string]string, 0, len(pending))
			for _, item := range pending {
				if item["agent_id"] == agentFilter {
					filtered = append(filtered, item)
				}
			}
			pending = filtered
		}
		writeJSON(conn, map[string]any{"items": pending})

	case "list":
		writeJSON(conn, map[string]any{"items": sessionManager.Snapshots()})

	case "inspect":
		agentID := strings.TrimSpace(req.ID)
		if agentID == "" {
			agentID = strings.TrimSpace(req.Agent)
		}
		if agentID == "" {
			writeJSON(conn, map[string]any{"error": "agent id is required"})
			return
		}
		snapshot, ok := sessionManager.Snapshot(agentID)
		if !ok {
			writeJSON(conn, map[string]any{"error": "agent not found"})
			return
		}
		writeJSON(conn, snapshot)

	case "history":
		agentID := strings.TrimSpace(req.ID)
		if agentID == "" {
			agentID = strings.TrimSpace(req.Agent)
		}
		if agentID == "" {
			writeJSON(conn, map[string]any{"error": "agent id is required"})
			return
		}
		history, ok := sessionManager.AgentHistory(agentID)
		if !ok {
			writeJSON(conn, map[string]any{"error": "agent not found"})
			return
		}
		window := strings.TrimSpace(req.Window)
		if window != "" {
			dur, err := time.ParseDuration(window)
			if err != nil {
				writeJSON(conn, map[string]any{"error": "invalid window"})
				return
			}
			cutoff := time.Now().Add(-dur)
			filtered := history[:0]
			for _, entry := range history {
				if entry.Timestamp.After(cutoff) {
					filtered = append(filtered, entry)
				}
			}
			history = filtered
		}
		writeJSON(conn, map[string]any{"agent_id": agentID, "history": history})

	case "killed":
		snapshots := sessionManager.Snapshots()
		killed := make([]any, 0, len(snapshots))
		for _, snapshot := range snapshots {
			if snapshot.Killed {
				killed = append(killed, snapshot)
			}
		}
		writeJSON(conn, map[string]any{"items": killed})

	case "unkill":
		agentID := strings.TrimSpace(req.Agent)
		if agentID == "" {
			agentID = strings.TrimSpace(req.ID)
		}
		if agentID == "" {
			writeJSON(conn, map[string]any{"error": "agent id is required"})
			return
		}
		sessionManager.Reset(agentID, "kill_switch")
		writeJSON(conn, map[string]any{"ok": true, "agent_id": agentID})

	default:
		writeJSON(conn, map[string]any{"error": "unknown agent op: " + op})
	}
}

func (s *Server) handleShutdown(conn net.Conn, line []byte) {
	var req struct {
		AdminToken string `json:"admin_token,omitempty"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid shutdown request"})
		return
	}
	if !s.authorizeControlAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	if s.shutdownFunc == nil {
		writeJSON(conn, map[string]any{"error": "shutdown unavailable"})
		return
	}
	writeJSON(conn, map[string]any{"ok": true, "message": "shutdown initiated"})
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.shutdownFunc()
	}()
}

// handleAuditSubscribe streams every decision to this connection until it closes.
// The connection sends {"type":"audit_subscribe"} once, then receives a stream
// of decision JSON objects (one per line) until it disconnects.
func (s *Server) handleAuditSubscribe(conn net.Conn) {
	ch := s.Subscribe()
	defer s.Unsubscribe(ch)

	writeJSON(conn, map[string]any{"subscribed": true})

	for event := range ch {
		decision := event.Decision
		writeJSON(conn, map[string]any{
			"effect":            string(decision.Effect),
			"agent_id":          event.AgentID,
			"session_id":        event.SessionID,
			"tool_id":           event.ToolID,
			"tool_name":         event.ToolName,
			"operation":         event.Operation,
			"rule_id":           decision.RuleID,
			"reason_code":       reasons.Normalize(decision.ReasonCode),
			"reason":            event.Reason,
			"record_id":         decision.DPRRecordID,
			"defer_token":       decision.DeferToken,
			"latency_ms":        decision.Latency.Milliseconds(),
			"timestamp":         decision.Timestamp.UTC().Format(time.RFC3339Nano),
			"policy_version":    decision.PolicyVersion,
			"incident_category": decision.IncidentCategory,
			"incident_severity": decision.IncidentSeverity,
			"blast_radius":      event.BlastRadius,
			"reversibility":     event.Reversibility,
			"principal_id":      event.PrincipalID,
			"principal_method":  event.PrincipalMethod,
			"args":              event.Args,
		})
	}
}

// handleCallbackSubscribe streams lifecycle callback events to this connection
// until it closes. This stream is optional and backward-compatible.
func (s *Server) handleCallbackSubscribe(conn net.Conn) {
	ch := s.SubscribeCallbacks()
	defer s.UnsubscribeCallbacks(ch)

	writeJSON(conn, map[string]any{"subscribed": true, "stream": "callbacks"})

	for event := range ch {
		writeJSON(conn, event)
	}
}

// broadcast sends a decision to all subscribed audit tail channels.
func (s *Server) broadcast(e auditEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// broadcastCallback sends callback events to all callback subscribers.
func (s *Server) broadcastCallback(e callbackEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.cbSubs {
		select {
		case ch <- e:
		default:
		}
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

func (s *Server) allowAgent(agentID string) bool {
	s.rlMu.Lock()
	limiter, ok := s.rl[agentID]
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(20), 40)
		s.rl[agentID] = limiter
	}
	s.rlMu.Unlock()
	return limiter.Allow()
}
