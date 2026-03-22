package daemon

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
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
