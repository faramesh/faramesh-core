package sdk

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/observe"
)

func TestCallbackSubscribeDecisionEventFires(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	cbClient := startSocketHandler(t, srv)
	defer cbClient.conn.Close()

	writeLine(t, cbClient.conn, `{"type":"callback_subscribe"}`)
	readJSONWithDeadline(t, cbClient, 500*time.Millisecond) // subscribed ack

	governClient := startSocketHandler(t, srv)
	defer governClient.conn.Close()
	writeLine(t, governClient.conn, `{"type":"govern","call_id":"c-1","agent_id":"a-1","session_id":"s-1","tool_id":"tool.echo","args":{"q":"hello"}}`)
	_ = readJSONWithDeadline(t, governClient, 500*time.Millisecond) // decision response

	ev := readJSONWithDeadline(t, cbClient, 500*time.Millisecond)
	if got := asString(ev["event_type"]); got != "decision" {
		t.Fatalf("event_type = %q, want decision", got)
	}
	if got := asString(ev["call_id"]); got != "c-1" {
		t.Fatalf("call_id = %q, want c-1", got)
	}
	if got := asString(ev["agent_id"]); got != "a-1" {
		t.Fatalf("agent_id = %q, want a-1", got)
	}
	if got := asString(ev["tool_id"]); got != "tool.echo" {
		t.Fatalf("tool_id = %q, want tool.echo", got)
	}
}

func TestCallbackSubscribeDeferResolvedEventFires(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	token := "tok-approve-1"
	_, err := srv.pipeline.DeferWorkflow().DeferWithToken(token, "agent-x", "tool.defer", "needs approval")
	if err != nil {
		t.Fatalf("seed defer token: %v", err)
	}

	cbClient := startSocketHandler(t, srv)
	defer cbClient.conn.Close()
	writeLine(t, cbClient.conn, `{"type":"callback_subscribe"}`)
	readJSONWithDeadline(t, cbClient, 500*time.Millisecond) // subscribed ack

	approveClient := startSocketHandler(t, srv)
	defer approveClient.conn.Close()
	writeLine(t, approveClient.conn, `{"type":"approve_defer","defer_token":"`+token+`","approved":true,"reason":"ship it"}`)
	resp := readJSONWithDeadline(t, approveClient, 500*time.Millisecond)
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("approve response not ok: %#v", resp)
	}

	ev := readJSONWithDeadline(t, cbClient, 500*time.Millisecond)
	if got := asString(ev["event_type"]); got != "defer_resolved" {
		t.Fatalf("event_type = %q, want defer_resolved", got)
	}
	if got := asString(ev["defer_token"]); got != token {
		t.Fatalf("defer_token = %q, want %s", got, token)
	}
	if got := asString(ev["status"]); got != "approved" {
		t.Fatalf("status = %q, want approved", got)
	}
}

func TestCallbackSubscriberDoesNotBlockGovernance(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())

	// Subscribe, read ack once, then stop reading to simulate a slow/stuck SDK callback consumer.
	cbClient := startSocketHandler(t, srv)
	defer cbClient.conn.Close()
	writeLine(t, cbClient.conn, `{"type":"callback_subscribe"}`)
	readJSONWithDeadline(t, cbClient, 500*time.Millisecond)

	governClient := startSocketHandler(t, srv)
	defer governClient.conn.Close()

	start := time.Now()
	for i := 0; i < 200; i++ {
		writeLine(t, governClient.conn, `{"type":"govern","call_id":"c-many","agent_id":"a-many","session_id":"s-many","tool_id":"tool.echo","args":{"n":1}}`)
		_ = readJSONWithDeadline(t, governClient, 2*time.Second)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("governance path slowed by callback subscriber: elapsed=%s", elapsed)
	}
}

func TestGovernedLogIncludesStructuredSchemaFields(t *testing.T) {
	coreObs, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(coreObs)
	srv := NewServer(core.NewPipeline(core.Config{Log: logger}), logger)
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"govern","call_id":"c-log-1","agent_id":"a-log-1","session_id":"s-log-1","tool_id":"tool.echo","args":{"q":"hello"}}`)
	_ = readJSONWithDeadline(t, client, 500*time.Millisecond)

	var entries []observer.LoggedEntry
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		entries = logs.All()
		if len(entries) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one log entry")
	}
	var fields map[string]interface{}
	for i := len(entries) - 1; i >= 0; i-- {
		candidate := entries[i].ContextMap()
		if candidate["event"] == observe.EventGovernDecision {
			fields = candidate
			break
		}
	}
	if fields == nil {
		t.Fatalf("expected a governance decision structured log entry")
	}
	if fields["log_schema"] != observe.GovernanceLogSchema {
		t.Fatalf("log_schema=%v", fields["log_schema"])
	}
	if fields["log_schema_version"] != observe.GovernanceLogSchemaVersion {
		t.Fatalf("log_schema_version=%v", fields["log_schema_version"])
	}
	if fields["event"] != observe.EventGovernDecision {
		t.Fatalf("event=%v", fields["event"])
	}
	for _, k := range []string{"agent_id", "session_id", "call_id", "tool_id", "effect", "reason_code"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("missing required field %q in governed structured log", k)
		}
	}
}

type testSocketClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func startSocketHandler(t *testing.T, srv *Server) *testSocketClient {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	go srv.handle(serverConn)
	return &testSocketClient{
		conn: clientConn,
		r:    bufio.NewReader(clientConn),
	}
}

func writeLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	_, err := conn.Write([]byte(line + "\n"))
	if err != nil {
		t.Fatalf("write line: %v", err)
	}
}

func readJSONWithDeadline(t *testing.T, c *testSocketClient, timeout time.Duration) map[string]any {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	defer c.conn.SetReadDeadline(time.Time{})

	line, err := c.r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal json line: %v (%s)", err, string(line))
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
