package sdk

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/delegate"
)

func newDelegateTestServer(t *testing.T) *Server {
	t.Helper()
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	srv.SetStandingAdminToken("test-admin")
	clk := func() time.Time { return time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC) }
	svc := delegate.NewService(delegate.NewMemoryStore(), delegate.DeriveKey([]byte("k")), 5, clk)
	srv.SetDelegateService(svc)
	return srv
}

func TestDelegate_RequiresAdminToken(t *testing.T) {
	srv := newDelegateTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","from_agent":"a","to_agent":"b"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "unauthorized") {
		t.Fatalf("expected unauthorized without admin_token, got %#v", resp)
	}
}

func TestDelegate_RejectsBadAdminToken(t *testing.T) {
	srv := newDelegateTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"wrong","from_agent":"a","to_agent":"b","ttl":"1h"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "unauthorized") {
		t.Fatalf("expected unauthorized, got %#v", resp)
	}
}

func TestDelegate_DisabledWhenServiceUnset(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	srv.SetStandingAdminToken("test-admin")
	// no SetDelegateService call
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"test-admin","from_agent":"a","to_agent":"b"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "delegate service unavailable") {
		t.Fatalf("expected service unavailable, got %#v", resp)
	}
}

func TestDelegate_GrantOK(t *testing.T) {
	srv := newDelegateTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"test-admin","from_agent":"a","to_agent":"b","scope":"stripe/*","ttl":"1h"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	tok, _ := resp["token"].(string)
	if !strings.HasPrefix(tok, "del_") {
		t.Fatalf("expected del_ token, got %#v", resp)
	}
	if from, _ := resp["from_agent"].(string); from != "a" {
		t.Errorf("from_agent: %v", from)
	}
}

func TestDelegate_RejectsUnknownOp(t *testing.T) {
	srv := newDelegateTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"explode","admin_token":"test-admin"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "unknown delegate op") {
		t.Fatalf("expected unknown op error, got %#v", resp)
	}
}

func TestDelegate_GrantValidationErrorCategory(t *testing.T) {
	srv := newDelegateTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	// self-delegation triggers ErrInvalidRequest.
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"test-admin","from_agent":"a","to_agent":"a","ttl":"1h"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if cat, _ := resp["category"].(string); cat != "invalid_request" {
		t.Fatalf("expected category=invalid_request, got %#v", resp)
	}
}

func TestDelegate_LifecycleOverSocket(t *testing.T) {
	srv := newDelegateTestServer(t)

	// Grant.
	c := startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"test-admin","from_agent":"a","to_agent":"b","scope":"*","ttl":"1h"}`)
	grantResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	tok, _ := grantResp["token"].(string)
	if tok == "" {
		t.Fatalf("no token: %#v", grantResp)
	}

	// Verify (valid).
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"delegate","op":"verify","admin_token":"test-admin","token":"`+tok+`"}`)
	verifyResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if v, _ := verifyResp["valid"].(bool); !v {
		t.Errorf("expected valid=true, got %#v", verifyResp)
	}

	// List.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"delegate","op":"list","admin_token":"test-admin","agent_id":"a"}`)
	listResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	dels, _ := listResp["delegations"].([]any)
	if len(dels) != 1 {
		t.Errorf("expected 1 delegation, got %d (%#v)", len(dels), listResp)
	}

	// Revoke.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"delegate","op":"revoke","admin_token":"test-admin","from_agent":"a","to_agent":"b"}`)
	revResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if rv, _ := revResp["revoked"].(bool); !rv {
		t.Errorf("expected revoked=true, got %#v", revResp)
	}

	// Verify after revoke is invalid.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"delegate","op":"verify","admin_token":"test-admin","token":"`+tok+`"}`)
	verify2 := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if v, _ := verify2["valid"].(bool); v {
		t.Errorf("expected valid=false after revoke, got %#v", verify2)
	}
}

func TestDelegate_ChainOverSocket(t *testing.T) {
	srv := newDelegateTestServer(t)

	for _, ft := range [][2]string{{"a", "b"}, {"b", "c"}, {"c", "d"}} {
		c := startSocketHandler(t, srv)
		writeLine(t, c.conn, `{"type":"delegate","op":"grant","admin_token":"test-admin","from_agent":"`+ft[0]+`","to_agent":"`+ft[1]+`","scope":"*","ttl":"1h"}`)
		readJSONWithDeadline(t, c, time.Second)
		c.conn.Close()
	}

	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"delegate","op":"chain","admin_token":"test-admin","agent_id":"d"}`)
	chainResp := readJSONWithDeadline(t, c, time.Second)
	chain, _ := chainResp["chain"].([]any)
	if len(chain) != 3 {
		t.Fatalf("expected 3-link chain, got %d (%#v)", len(chain), chainResp)
	}
}
