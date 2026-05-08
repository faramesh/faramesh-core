package sdk

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/schedule"
)

func newScheduleTestServer(t *testing.T) *Server {
	t.Helper()
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	srv.SetStandingAdminToken("test-admin")
	clk := func() time.Time { return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC) }
	counter := 0
	gen := func() string {
		counter++
		return "sched_" + strconv.Itoa(counter)
	}
	svc := schedule.NewService(schedule.NewMemoryStore(), clk, gen)
	srv.SetScheduleService(svc)
	return srv
}

func TestSchedule_RequiresAdminToken(t *testing.T) {
	srv := newScheduleTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"create","tool":"t/op","agent":"a"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "unauthorized") {
		t.Fatalf("expected unauthorized, got %#v", resp)
	}
}

func TestSchedule_DisabledWhenServiceUnset(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	srv.SetStandingAdminToken("test-admin")
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"t/op","agent":"a"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "schedule service unavailable") {
		t.Fatalf("expected service unavailable, got %#v", resp)
	}
}

func TestSchedule_RejectsUnknownOp(t *testing.T) {
	srv := newScheduleTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"explode","admin_token":"test-admin"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "unknown schedule op") {
		t.Fatalf("expected unknown op error, got %#v", resp)
	}
}

func TestSchedule_CreateOK_AndCategorizesErrors(t *testing.T) {
	srv := newScheduleTestServer(t)
	c := startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"stripe/refund","agent":"agent","at":"+1h","reeval":true}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if id, _ := resp["id"].(string); !strings.HasPrefix(id, "sched_") {
		t.Fatalf("expected sched_ id, got %#v", resp)
	}
	if status, _ := resp["status"].(string); status != "scheduled" {
		t.Errorf("expected status=scheduled, got %s", status)
	}

	// Validation error path with category surfaced.
	c = startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"","agent":"agent"}`)
	resp = readJSONWithDeadline(t, c, time.Second)
	if cat, _ := resp["category"].(string); cat != "invalid_request" {
		t.Errorf("expected category=invalid_request, got %#v", resp)
	}
}

func TestSchedule_LifecycleOverSocket(t *testing.T) {
	srv := newScheduleTestServer(t)

	// Create.
	c := startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"t/op","agent":"agent","at":"+1h"}`)
	createResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	id, _ := createResp["id"].(string)
	if id == "" {
		t.Fatalf("no id: %#v", createResp)
	}

	// List.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"list","admin_token":"test-admin","agent_id":"agent"}`)
	listResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	entries, _ := listResp["schedules"].([]any)
	if len(entries) != 1 {
		t.Errorf("expected 1 in list, got %d", len(entries))
	}

	// Inspect.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"inspect","admin_token":"test-admin","id":"`+id+`"}`)
	inspectResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if got, _ := inspectResp["id"].(string); got != id {
		t.Errorf("inspect mismatch: %#v", inspectResp)
	}

	// Cancel.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"cancel","admin_token":"test-admin","schedule_id":"`+id+`"}`)
	cancelResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	if status, _ := cancelResp["status"].(string); status != "cancelled" {
		t.Errorf("expected status=cancelled, got %#v", cancelResp)
	}

	// Cancel again should be invalid_status.
	c = startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"cancel","admin_token":"test-admin","schedule_id":"`+id+`"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if cat, _ := resp["category"].(string); cat != "invalid_status" {
		t.Errorf("expected category=invalid_status on double cancel, got %#v", resp)
	}
}

func TestSchedule_PendingAndApprove(t *testing.T) {
	srv := newScheduleTestServer(t)

	// Create.
	c := startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"t/op","agent":"a","at":"+1h"}`)
	createResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	id, _ := createResp["id"].(string)

	// Move to pending_approval directly via the service (executor would do this).
	if _, err := srv.schedule.MarkPendingApproval(id, "policy deferred"); err != nil {
		t.Fatalf("mark pending: %v", err)
	}

	// Pending list shows it.
	c = startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"pending","admin_token":"test-admin"}`)
	pendResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	entries, _ := pendResp["pending"].([]any)
	if len(entries) != 1 {
		t.Errorf("expected 1 pending, got %d (%#v)", len(entries), pendResp)
	}

	// Approve.
	c = startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"approve","admin_token":"test-admin","schedule_id":"`+id+`","approver":"ops-team"}`)
	approveResp := readJSONWithDeadline(t, c, time.Second)
	if status, _ := approveResp["status"].(string); status != "approved" {
		t.Errorf("expected status=approved, got %#v", approveResp)
	}
	if by, _ := approveResp["approved_by"].(string); by != "ops-team" {
		t.Errorf("expected approved_by=ops-team, got %#v", approveResp)
	}
}

func TestSchedule_HistoryOverSocket(t *testing.T) {
	srv := newScheduleTestServer(t)

	c := startSocketHandler(t, srv)
	writeLine(t, c.conn, `{"type":"schedule","op":"create","admin_token":"test-admin","tool":"t/op","agent":"a"}`)
	createResp := readJSONWithDeadline(t, c, time.Second)
	c.conn.Close()
	id, _ := createResp["id"].(string)

	// Record execution via the service.
	if _, err := srv.schedule.MarkExecuted(id, true, "ok"); err != nil {
		t.Fatalf("mark executed: %v", err)
	}

	c = startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"history","admin_token":"test-admin","window":"1h"}`)
	histResp := readJSONWithDeadline(t, c, time.Second)
	entries, _ := histResp["history"].([]any)
	if len(entries) != 1 {
		t.Errorf("expected 1 in history, got %d (%#v)", len(entries), histResp)
	}
}

func TestSchedule_Inspect_NotFound(t *testing.T) {
	srv := newScheduleTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"inspect","admin_token":"test-admin","id":"sched_nope"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "not found") {
		t.Errorf("expected not-found error, got %#v", resp)
	}
}

func TestSchedule_Cancel_RequiresID(t *testing.T) {
	srv := newScheduleTestServer(t)
	c := startSocketHandler(t, srv)
	defer c.conn.Close()
	writeLine(t, c.conn, `{"type":"schedule","op":"cancel","admin_token":"test-admin"}`)
	resp := readJSONWithDeadline(t, c, time.Second)
	if errStr, _ := resp["error"].(string); !strings.Contains(errStr, "schedule_id is required") {
		t.Errorf("expected required-id error, got %#v", resp)
	}
}
