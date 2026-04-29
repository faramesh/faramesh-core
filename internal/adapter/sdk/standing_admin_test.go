package sdk

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/standing"
)

func TestStandingGrantListRequiresAdminToken(t *testing.T) {
	reg := standing.NewRegistry()
	p := core.NewPipeline(core.Config{Standing: reg})
	srv := NewServer(p, zap.NewNop())
	srv.SetStandingAdminToken("prod-admin-token")

	c := startSocketHandler(t, srv)
	defer c.conn.Close()

	writeLine(t, c.conn, `{"type":"standing_grant_list"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "unauthorized") {
		t.Fatalf("expected unauthorized without admin_token, got %#v", resp)
	}

	c2 := startSocketHandler(t, srv)
	defer c2.conn.Close()
	writeLine(t, c2.conn, `{"type":"standing_grant_list","admin_token":"wrong"}`)
	resp2 := readJSONWithDeadline(t, c2, time.Second)
	errStr2, _ := resp2["error"].(string)
	if !strings.Contains(errStr2, "unauthorized") {
		t.Fatalf("expected unauthorized for bad token, got %#v", resp2)
	}

	c3 := startSocketHandler(t, srv)
	defer c3.conn.Close()
	writeLine(t, c3.conn, `{"type":"standing_grant_list","admin_token":"prod-admin-token"}`)
	resp3 := readJSONWithDeadline(t, c3, time.Second)
	if ok, _ := resp3["ok"].(bool); !ok {
		t.Fatalf("expected ok list, got %#v", resp3)
	}
}

func TestStandingGrantDisabledWhenNoAdminConfigured(t *testing.T) {
	reg := standing.NewRegistry()
	p := core.NewPipeline(core.Config{Standing: reg})
	srv := NewServer(p, zap.NewNop())
	// standingAdminToken left empty
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"standing_grant_list","admin_token":"anything"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "standing_grants_admin_unconfigured") {
		t.Fatalf("expected unconfigured error, got %#v", resp)
	}
}
