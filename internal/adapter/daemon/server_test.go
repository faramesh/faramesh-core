package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
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
}
