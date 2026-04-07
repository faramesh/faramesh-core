package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func mcpPackageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Dir(file)
}

// chdirMCP sets working directory to this package so `go run ./testdata/stdio_echo` resolves.
func chdirMCP(t *testing.T) {
	t.Helper()
	d := mcpPackageDir(t)
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func TestStdioGateway_toolsCallDeniedNoSubprocessResult(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	msg := MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"danger/x","arguments":{}}`),
	}
	out, err := g.ProcessRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32003 {
		t.Fatalf("expected deny: %+v", out)
	}
}

func TestStdioGateway_toolsCallPermitEcho(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	msg := MCPMessage{
		JSONRPC: "2.0",
		ID:      "rid-1",
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"safe/tool","arguments":{}}`),
	}
	out, err := g.ProcessRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
	if out.ID != "rid-1" {
		t.Fatalf("id want rid-1 got %v", out.ID)
	}
	var res map[string]any
	if err := json.Unmarshal(out.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res["echo"] != true {
		t.Fatalf("result: %+v", res)
	}
}

func TestStdioGateway_nonToolForwarded(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	msg := MCPMessage{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "ping",
		Params:  json.RawMessage(`{}`),
	}
	out, err := g.ProcessRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected error: %+v", out.Error)
	}
}

func TestStdioGateway_ProcessStdioLine_batchTwoDeniesNoSubprocess(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	line := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger/x","arguments":{}}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"y/z","arguments":{}}}]`
	out, err := g.ProcessStdioLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var batch []MCPMessage
	if err := json.Unmarshal(out, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch) != 2 || batch[0].Error == nil || batch[1].Error == nil {
		t.Fatalf("expected two errors: %+v", batch)
	}
}

func TestStdioGateway_ProcessStdioLine_batchTwoPermitsEcho(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	line := `[{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}},` +
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}]`
	out, err := g.ProcessStdioLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var batch []MCPMessage
	if err := json.Unmarshal(out, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch) != 2 {
		t.Fatalf("batch len: %d", len(batch))
	}
	for i, m := range batch {
		if m.Error != nil {
			t.Fatalf("batch %d: %+v", i, m.Error)
		}
		var res map[string]any
		if err := json.Unmarshal(m.Result, &res); err != nil {
			t.Fatal(err)
		}
		if res["echo"] != true {
			t.Fatalf("batch %d result: %+v", i, res)
		}
	}
}

func TestStdioGateway_ProcessStdioLine_batchEmpty(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	out, err := g.ProcessStdioLine([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != `[]` {
		t.Fatalf("got %q", out)
	}
}

func TestStdioGateway_ProcessStdioLine_notificationNoResponse(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	start := time.Now()
	out, err := g.ProcessStdioLine([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no response line, got %q", string(out))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("notification path should not block, took %s", elapsed)
	}
}

func TestStdioGateway_forwardsUnsolicitedServerNotification(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_notify"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	msg := MCPMessage{
		JSONRPC: "2.0",
		ID:      42,
		Method:  "ping",
		Params:  json.RawMessage(`{}`),
	}
	out, err := g.ProcessRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected error response: %+v", out.Error)
	}

	select {
	case line := <-g.Outbound():
		var up MCPMessage
		if err := json.Unmarshal(line, &up); err != nil {
			t.Fatalf("invalid outbound message: %v", err)
		}
		if up.Method != "notifications/progress" {
			t.Fatalf("expected notifications/progress, got %q", up.Method)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected unsolicited upstream notification")
	}
}

func TestStdioGateway_ProcessStdioLine_responseNoResponse(t *testing.T) {
	chdirMCP(t)
	g, err := NewStdioGateway(testMCPPipeline(t), "agent-1", zap.NewNop(), []string{"go", "run", "./testdata/stdio_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	out, err := g.ProcessStdioLine([]byte(`{"jsonrpc":"2.0","id":"srv-1","result":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no response line, got %q", string(out))
	}
}
