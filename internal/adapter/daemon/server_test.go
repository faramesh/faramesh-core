package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGovernRoundTripJSONCodec(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: '1.0'
agent-id: test-agent
default_effect: permit
rules: []
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	srv := NewServer(Config{Pipeline: pipeline})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.GracefulStop()

	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Govern(ctx, &GovernRequest{
		CallId:    "govern-1",
		AgentId:   "agent-1",
		SessionId: "session-1",
		ToolId:    "read_customer",
		ArgsJson:  `{"id":"cust-1"}`,
	})
	if err != nil {
		t.Fatalf("govern call failed: %v", err)
	}
	if resp.Effect == "" {
		t.Fatalf("expected non-empty effect")
	}
	if resp.DaemonApiVersion != APIVersion {
		t.Fatalf("expected daemon_api_version=%q, got %q", APIVersion, resp.DaemonApiVersion)
	}
	if !reasons.IsKnown(resp.ReasonCode) {
		t.Fatalf("expected canonical reason_code in daemon response, got %q", resp.ReasonCode)
	}
}

func TestGovernRoundTripWithPrincipalToken(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: '1.0'
agent-id: test-agent
rules:
  - id: permit-idp-principal
    match:
      tool: "read_customer"
      when: "principal.verified && principal.org == 'acme'"
    effect: permit
default_effect: deny
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	srv := NewServer(Config{
		Pipeline: pipeline,
		PrincipalResolver: func(ctx context.Context, token string) (*principal.Identity, error) {
			_ = ctx
			if token != "good-token" {
				return nil, context.DeadlineExceeded
			}
			return &principal.Identity{ID: "user-abc", Org: "acme", Verified: true, Method: "okta_oidc"}, nil
		},
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.GracefulStop()

	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Govern(ctx, &GovernRequest{
		CallId:         "govern-principal-1",
		AgentId:        "agent-1",
		SessionId:      "session-1",
		ToolId:         "read_customer",
		PrincipalToken: "good-token",
		ArgsJson:       `{"id":"cust-1"}`,
	})
	if err != nil {
		t.Fatalf("govern call failed: %v", err)
	}
	if strings.ToUpper(resp.Effect) != "PERMIT" {
		t.Fatalf("expected PERMIT, got %s (%s)", resp.Effect, resp.Reason)
	}
}

func TestGovernAcceptsMatchingMajorAPIVersion(t *testing.T) {
	srv, lis := testDaemonServer(t)
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := client.Govern(ctx, &GovernRequest{
		CallId:     "govern-v1",
		AgentId:    "agent-1",
		SessionId:  "session-1",
		ToolId:     "read_customer",
		ApiVersion: "1.2",
	})
	if err != nil {
		t.Fatalf("expected accepted version, got err: %v", err)
	}
	if resp.DaemonApiVersion != APIVersion {
		t.Fatalf("expected daemon_api_version=%q, got %q", APIVersion, resp.DaemonApiVersion)
	}
}

func TestGovernRejectsUnsupportedMajorAPIVersion(t *testing.T) {
	srv, lis := testDaemonServer(t)
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Govern(ctx, &GovernRequest{
		CallId:     "govern-v2",
		AgentId:    "agent-1",
		SessionId:  "session-1",
		ToolId:     "read_customer",
		ApiVersion: "2.0",
	})
	if err == nil {
		t.Fatalf("expected unsupported major version error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %s (%v)", st.Code(), err)
	}
}

func TestPushPolicySuccess(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(testPolicyPermitAll))
	if err != nil {
		t.Fatalf("load initial policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	srv := NewServer(Config{Pipeline: pipeline, PolicyAdminToken: "secret-token"})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pushResp, err := client.PushPolicy(ctx, &PushPolicyRequest{
		AdminToken: "secret-token",
		PolicyYaml: testPolicyDenyAll,
	})
	if err != nil {
		t.Fatalf("push policy failed: %v", err)
	}
	if !pushResp.Applied {
		t.Fatalf("expected push to apply, got errors: %v", pushResp.Errors)
	}
	if pushResp.PolicyVersion == "" || pushResp.PolicyHash == "" {
		t.Fatalf("expected policy version/hash in response")
	}
	decision, err := client.Govern(ctx, &GovernRequest{
		CallId:    "govern-after-push",
		AgentId:   "agent-1",
		SessionId: "session-1",
		ToolId:    "read_customer",
		ArgsJson:  `{"id":"cust-1"}`,
	})
	if err != nil {
		t.Fatalf("govern after push failed: %v", err)
	}
	if strings.ToUpper(decision.Effect) != "DENY" {
		t.Fatalf("expected DENY after pushed policy, got %s", decision.Effect)
	}
}

func TestPushPolicyRejectsInvalidPolicy(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(testPolicyPermitAll))
	if err != nil {
		t.Fatalf("load initial policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	srv := NewServer(Config{Pipeline: pipeline, PolicyAdminToken: "secret-token"})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := NewFarameshDaemonClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pushResp, err := client.PushPolicy(ctx, &PushPolicyRequest{
		AdminToken: "secret-token",
		PolicyYaml: testPolicyInvalidExpr,
	})
	if err != nil {
		t.Fatalf("push policy failed: %v", err)
	}
	if pushResp.Applied {
		t.Fatalf("expected invalid policy rejection")
	}
	if len(pushResp.Errors) == 0 {
		t.Fatalf("expected rejection errors")
	}
	decision, err := client.Govern(ctx, &GovernRequest{
		CallId:    "govern-after-invalid",
		AgentId:   "agent-1",
		SessionId: "session-1",
		ToolId:    "read_customer",
		ArgsJson:  `{"id":"cust-1"}`,
	})
	if err != nil {
		t.Fatalf("govern after invalid push failed: %v", err)
	}
	if strings.ToUpper(decision.Effect) != "PERMIT" {
		t.Fatalf("expected existing policy to remain active, got %s", decision.Effect)
	}
}

func TestPushPolicyNoDowntimeDuringConcurrentGovern(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(testPolicyPermitAll))
	if err != nil {
		t.Fatalf("load initial policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	srv := NewServer(Config{Pipeline: pipeline, PolicyAdminToken: "secret-token"})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	conn, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := NewFarameshDaemonClient(conn)
	var failed atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 120; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			_, err := client.Govern(ctx, &GovernRequest{
				CallId:    "loop-govern",
				AgentId:   "agent-1",
				SessionId: "session-1",
				ToolId:    "read_customer",
				ArgsJson:  `{"id":"cust-1"}`,
			})
			cancel()
			if err != nil {
				failed.Store(1)
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pushResp, err := client.PushPolicy(ctx, &PushPolicyRequest{
		AdminToken: "secret-token",
		PolicyYaml: testPolicyDenyAll,
	})
	if err != nil {
		t.Fatalf("push policy failed: %v", err)
	}
	if !pushResp.Applied {
		t.Fatalf("expected push apply during traffic, got errors: %v", pushResp.Errors)
	}
	<-done
	if failed.Load() != 0 {
		t.Fatalf("govern path failed while policy push happened")
	}
}

func TestWaitForApprovalTimeoutAllowsLateApprovalResolution(t *testing.T) {
	wf := deferwork.NewWorkflow("")
	pipeline := core.NewPipeline(core.Config{Defers: wf})
	srv := NewServer(Config{Pipeline: pipeline})

	const token = "tok-timeout-approve"
	if _, err := wf.DeferWithToken(token, "agent-approve", "tool-approve", "needs review"); err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	approved, err := srv.waitForApproval(timeoutCtx, token)
	if err == nil {
		t.Fatalf("expected timeout error while defer is pending")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want context deadline exceeded", err)
	}
	if approved {
		t.Fatalf("approved = true, want false on timeout")
	}

	st, pending := wf.Status(token)
	if st != deferwork.StatusPending || !pending {
		t.Fatalf("status after timeout = (%q, %v), want (%q, true)", st, pending, deferwork.StatusPending)
	}

	if err := wf.Resolve(token, true, "", "late approval"); err != nil {
		t.Fatalf("late Resolve() error = %v", err)
	}

	resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer resumeCancel()
	approved, err = srv.waitForApproval(resumeCtx, token)
	if err != nil {
		t.Fatalf("waitForApproval() after late approval error = %v", err)
	}
	if !approved {
		t.Fatalf("approved = false, want true after late approval")
	}

	st, pending = wf.Status(token)
	if st != deferwork.StatusApproved || pending {
		t.Fatalf("final status = (%q, %v), want (%q, false)", st, pending, deferwork.StatusApproved)
	}
}

func TestWaitForApprovalTimeoutAllowsLateDenialResolution(t *testing.T) {
	wf := deferwork.NewWorkflow("")
	pipeline := core.NewPipeline(core.Config{Defers: wf})
	srv := NewServer(Config{Pipeline: pipeline})

	const token = "tok-timeout-deny"
	if _, err := wf.DeferWithToken(token, "agent-deny", "tool-deny", "needs review"); err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	approved, err := srv.waitForApproval(timeoutCtx, token)
	if err == nil {
		t.Fatalf("expected timeout error while defer is pending")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want context deadline exceeded", err)
	}
	if approved {
		t.Fatalf("approved = true, want false on timeout")
	}

	st, pending := wf.Status(token)
	if st != deferwork.StatusPending || !pending {
		t.Fatalf("status after timeout = (%q, %v), want (%q, true)", st, pending, deferwork.StatusPending)
	}

	if err := wf.Resolve(token, false, "", "late denial"); err != nil {
		t.Fatalf("late Resolve() error = %v", err)
	}

	resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer resumeCancel()
	approved, err = srv.waitForApproval(resumeCtx, token)
	if err != nil {
		t.Fatalf("waitForApproval() after late denial error = %v", err)
	}
	if approved {
		t.Fatalf("approved = true, want false after late denial")
	}

	st, pending = wf.Status(token)
	if st != deferwork.StatusDenied || pending {
		t.Fatalf("final status = (%q, %v), want (%q, false)", st, pending, deferwork.StatusDenied)
	}
}

const testPolicyPermitAll = `
faramesh-version: "1.0"
agent-id: "test-agent"
default_effect: permit
rules: []
`

const testPolicyDenyAll = `
faramesh-version: "1.0"
agent-id: "test-agent"
default_effect: deny
rules: []
`

const testPolicyInvalidExpr = `
faramesh-version: "1.0"
agent-id: "test-agent"
default_effect: deny
rules:
  - id: broken
    match:
      tool: "*"
      when: "args.x =="
    effect: permit
`

func testDaemonServer(t *testing.T) (*Server, net.Listener) {
	t.Helper()
	doc, version, err := policy.LoadBytes([]byte(testPolicyPermitAll))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
	srv := NewServer(Config{Pipeline: pipeline})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return srv, lis
}
