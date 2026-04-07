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
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
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

func TestStatusRequestReturnsRuntimeSnapshot(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"status"}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)

	if running, _ := resp["running"].(bool); !running {
		t.Fatalf("running = %v, want true", resp["running"])
	}
	if _, ok := resp["policy_loaded"].(bool); !ok {
		t.Fatalf("policy_loaded missing or wrong type: %#v", resp)
	}
	if _, ok := resp["dpr_healthy"].(bool); !ok {
		t.Fatalf("dpr_healthy missing or wrong type: %#v", resp)
	}
	if _, ok := resp["active_sessions"].(float64); !ok {
		t.Fatalf("active_sessions missing or wrong type: %#v", resp)
	}
	if _, ok := resp["uptime_seconds"].(float64); !ok {
		t.Fatalf("uptime_seconds missing or wrong type: %#v", resp)
	}
}

func TestSessionOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"session","op":"open","agent_id":"a-1","budget":25,"ttl":"30m"}`)
	openResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(openResp["agent_id"]); got != "a-1" {
		t.Fatalf("open agent_id=%q", got)
	}
	if open, _ := openResp["open"].(bool); !open {
		t.Fatalf("expected open=true: %#v", openResp)
	}

	writeLine(t, client.conn, `{"type":"session","op":"purpose_declare","agent_id":"a-1","purpose":"support"}`)
	purposeResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := purposeResp["purposes"].([]any); !ok {
		t.Fatalf("purpose response missing purposes: %#v", purposeResp)
	}

	writeLine(t, client.conn, `{"type":"session","op":"budget_get","agent_id":"a-1"}`)
	budgetResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got, _ := budgetResp["budget"].(float64); got != 25 {
		t.Fatalf("budget=%v, want 25", budgetResp["budget"])
	}

	writeLine(t, client.conn, `{"type":"session","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["sessions"].([]any); !ok {
		t.Fatalf("list response missing sessions: %#v", listResp)
	}

	writeLine(t, client.conn, `{"type":"session","op":"inspect","agent_id":"a-1"}`)
	inspectResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(inspectResp["agent_id"]); got != "a-1" {
		t.Fatalf("inspect agent_id=%q", got)
	}
	if _, ok := inspectResp["call_count"].(float64); !ok {
		t.Fatalf("inspect missing call_count: %#v", inspectResp)
	}

	writeLine(t, client.conn, `{"type":"session","op":"reset","agent_id":"a-1","counter":"all"}`)
	resetResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if ok, _ := resetResp["ok"].(bool); !ok {
		t.Fatalf("reset not ok: %#v", resetResp)
	}

	writeLine(t, client.conn, `{"type":"session","op":"close","agent_id":"a-1"}`)
	closeResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if open, _ := closeResp["open"].(bool); open {
		t.Fatalf("expected open=false: %#v", closeResp)
	}
}

func TestModelOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"model","op":"register","name":"gpt-4o","fingerprint":"abc123","provider":"openai","version":"2026-03"}`)
	registerResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if ok, _ := registerResp["ok"].(bool); !ok {
		t.Fatalf("register not ok: %#v", registerResp)
	}

	writeLine(t, client.conn, `{"type":"model","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["models"].([]any); !ok {
		t.Fatalf("list response missing models: %#v", listResp)
	}

	writeLine(t, client.conn, `{"type":"model","op":"verify","agent":"a-1"}`)
	verifyResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if verified, _ := verifyResp["verified"].(bool); !verified {
		t.Fatalf("expected verified=true: %#v", verifyResp)
	}

	writeLine(t, client.conn, `{"type":"model","op":"consistency","agent":"a-1","window":"24h"}`)
	consistencyResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(consistencyResp["status"]); got != "consistent" {
		t.Fatalf("consistency status=%q", got)
	}

	writeLine(t, client.conn, `{"type":"model","op":"alert","agent":"a-1"}`)
	alertResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := alertResp["alerts"].([]any); !ok {
		t.Fatalf("alert response missing alerts: %#v", alertResp)
	}
}

func TestProvenanceOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"provenance","op":"sign","agent_id":"a-1","model":"gpt-4o","framework":"langgraph","tools":"read,write","signing_key":"k1"}`)
	signResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(signResp["agent_id"]); got != "a-1" {
		t.Fatalf("sign agent_id=%q", got)
	}
	if asString(signResp["record_id"]) == "" {
		t.Fatalf("missing record_id in sign response: %#v", signResp)
	}

	writeLine(t, client.conn, `{"type":"provenance","op":"verify","agent_id":"a-1"}`)
	verifyResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if verified, _ := verifyResp["verified"].(bool); !verified {
		t.Fatalf("expected verified=true: %#v", verifyResp)
	}

	writeLine(t, client.conn, `{"type":"provenance","op":"inspect","agent_id":"a-1"}`)
	inspectResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(inspectResp["agent_id"]); got != "a-1" {
		t.Fatalf("inspect agent_id=%q", got)
	}

	writeLine(t, client.conn, `{"type":"provenance","op":"diff","agent_id":"a-1"}`)
	diffResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(diffResp["drift"]); got != "none" {
		t.Fatalf("diff drift=%q", got)
	}

	writeLine(t, client.conn, `{"type":"provenance","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["records"].([]any); !ok {
		t.Fatalf("list response missing records: %#v", listResp)
	}
}

func TestIdentityOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"identity","op":"verify","spiffe_id":"spiffe://example.org/agent/a-1"}`)
	verifyResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if verified, _ := verifyResp["verified"].(bool); !verified {
		t.Fatalf("expected verified=true: %#v", verifyResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"trust","domain":"example.org","bundle":"bundle.pem"}`)
	trustResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(trustResp["trust_level"]); got == "" {
		t.Fatalf("missing trust_level: %#v", trustResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"attest","workload":"payments-worker"}`)
	attestResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if attested, _ := attestResp["attested"].(bool); !attested {
		t.Fatalf("expected attested=true: %#v", attestResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"federation_add","idp":"https://idp.example","client_id":"cid","scope":"openid"}`)
	addResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if ok, _ := addResp["ok"].(bool); !ok {
		t.Fatalf("federation add not ok: %#v", addResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"federation_list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["federations"].([]any); !ok {
		t.Fatalf("missing federations list: %#v", listResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"whoami"}`)
	whoamiResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(whoamiResp["workload"]); got != "payments-worker" {
		t.Fatalf("whoami workload=%q", got)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"trust_level"}`)
	trustLevelResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(trustLevelResp["trust_level"]); got == "" {
		t.Fatalf("missing trust level: %#v", trustLevelResp)
	}

	writeLine(t, client.conn, `{"type":"identity","op":"federation_revoke","idp":"https://idp.example"}`)
	revokeResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if ok, _ := revokeResp["ok"].(bool); !ok {
		t.Fatalf("federation revoke not ok: %#v", revokeResp)
	}
}

func TestCredentialOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"credential","op":"register","name":"stripe","key":"sk_live_x","scope":"payments","max_scope":"payments:write"}`)
	registerResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(registerResp["name"]); got != "stripe" {
		t.Fatalf("register name=%q", got)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["credentials"].([]any); !ok {
		t.Fatalf("missing credentials list: %#v", listResp)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"inspect","name":"stripe"}`)
	inspectResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(inspectResp["name"]); got != "stripe" {
		t.Fatalf("inspect name=%q", got)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"rotate","name":"stripe","key":"sk_live_new"}`)
	rotateResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(rotateResp["key"]); got != "sk_live_new" {
		t.Fatalf("rotate key=%q", got)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"health"}`)
	healthResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if healthy, _ := healthResp["healthy"].(bool); !healthy {
		t.Fatalf("health not healthy: %#v", healthResp)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"audit","name":"stripe","window":"24h"}`)
	auditResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := auditResp["events"].([]any); !ok {
		t.Fatalf("audit missing events: %#v", auditResp)
	}

	writeLine(t, client.conn, `{"type":"credential","op":"revoke","name":"stripe"}`)
	revokeResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(revokeResp["status"]); got != "revoked" {
		t.Fatalf("revoke status=%q", got)
	}
}

func TestCredentialRoutingMapOverSocket(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "sdk-credential-map"
tools:
  stripe/refund:
    tags: ["credential:broker", "credential:required", "credential:scope:payments"]
  http/get:
    tags: ["read_only"]
rules:
  - id: allow-all
    match:
      tool: "*"
    effect: permit
default_effect: deny
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	envBroker := &credential.EnvBroker{}
	router := credential.NewRouter([]credential.Broker{envBroker}, envBroker)
	if err := router.AddRoute("*", "env"); err != nil {
		t.Fatalf("add route: %v", err)
	}

	p := core.NewPipeline(core.Config{
		Engine:           policy.NewAtomicEngine(engine),
		CredentialRouter: router,
	})
	srv := NewServer(p, zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"credential","op":"routing_map"}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)

	if configured, _ := resp["router_configured"].(bool); !configured {
		t.Fatalf("expected router_configured=true: %#v", resp)
	}
	if tc, _ := resp["tool_count"].(float64); int(tc) != 2 {
		t.Fatalf("expected tool_count=2: %#v", resp)
	}

	toolsRaw, ok := resp["tools"].([]any)
	if !ok {
		t.Fatalf("missing tools list: %#v", resp)
	}

	byTool := map[string]map[string]any{}
	for _, raw := range toolsRaw {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		toolID := asString(entry["tool_id"])
		if toolID != "" {
			byTool[toolID] = entry
		}
	}

	stripe := byTool["stripe/refund"]
	if stripe == nil {
		t.Fatalf("missing stripe/refund in diagnostics: %#v", resp)
	}
	if enabled, _ := stripe["broker_enabled"].(bool); !enabled {
		t.Fatalf("expected stripe/refund broker_enabled=true: %#v", stripe)
	}
	if required, _ := stripe["required"].(bool); !required {
		t.Fatalf("expected stripe/refund required=true: %#v", stripe)
	}
	if scope := asString(stripe["scope"]); scope != "payments" {
		t.Fatalf("expected stripe/refund scope=payments, got %q", scope)
	}

	httpGet := byTool["http/get"]
	if httpGet == nil {
		t.Fatalf("missing http/get in diagnostics: %#v", resp)
	}
	if enabled, _ := httpGet["broker_enabled"].(bool); enabled {
		t.Fatalf("expected http/get broker_enabled=false: %#v", httpGet)
	}
}

func TestIncidentOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"incident","op":"declare","agent":"a-1","severity":"high","reason":"risk"}`)
	declareResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	incidentID := asString(declareResp["id"])
	if incidentID == "" {
		t.Fatalf("declare missing id: %#v", declareResp)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["incidents"].([]any); !ok {
		t.Fatalf("list missing incidents: %#v", listResp)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"inspect","id":"`+incidentID+`"}`)
	inspectResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(inspectResp["id"]); got != incidentID {
		t.Fatalf("inspect id=%q", got)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"evidence","id":"`+incidentID+`"}`)
	evidenceResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := evidenceResp["evidence"].([]any); !ok {
		t.Fatalf("evidence missing list: %#v", evidenceResp)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"playbook","id":"`+incidentID+`"}`)
	playbookResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := playbookResp["steps"].([]any); !ok {
		t.Fatalf("playbook missing steps: %#v", playbookResp)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"isolate","agent_id":"a-1"}`)
	isolateResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := isolateResp["isolated_incidents"].(float64); !ok {
		t.Fatalf("isolate missing isolated_incidents: %#v", isolateResp)
	}

	writeLine(t, client.conn, `{"type":"incident","op":"resolve","incident_id":"`+incidentID+`"}`)
	resolveResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(resolveResp["status"]); got != "resolved" {
		t.Fatalf("resolve status=%q", got)
	}
}

func TestCompensateOpsLifecycleOverSocket(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"type":"compensate","op":"apply","id":"cmp-1"}`)
	applyResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(applyResp["status"]); got != "applied" {
		t.Fatalf("apply status=%q", got)
	}

	writeLine(t, client.conn, `{"type":"compensate","op":"status","id":"cmp-1"}`)
	statusResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(statusResp["status"]); got == "" {
		t.Fatalf("status missing: %#v", statusResp)
	}

	writeLine(t, client.conn, `{"type":"compensate","op":"inspect","id":"cmp-1"}`)
	inspectResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(inspectResp["id"]); got != "cmp-1" {
		t.Fatalf("inspect id=%q", got)
	}

	writeLine(t, client.conn, `{"type":"compensate","op":"retry","id":"cmp-1","from_step":"rollback"}`)
	retryResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(retryResp["status"]); got != "retrying" {
		t.Fatalf("retry status=%q", got)
	}

	writeLine(t, client.conn, `{"type":"compensate","op":"list"}`)
	listResp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if _, ok := listResp["compensations"].([]any); !ok {
		t.Fatalf("list missing compensations: %#v", listResp)
	}
}

func TestGovernJSONRPCCompatibility(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	writeLine(t, client.conn, `{"jsonrpc":"2.0","id":1,"method":"govern","params":{"agent_id":"a-rpc","session_id":"s-rpc","tool":"tool","operation":"echo","args":{"q":"hello"}}}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(resp["jsonrpc"]); got != "2.0" {
		t.Fatalf("jsonrpc=%q", got)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing jsonrpc result: %#v", resp)
	}
	if got := asString(result["effect"]); got == "" {
		t.Fatalf("missing result.effect: %#v", result)
	}
}

func TestGovernBurstRateLimitedByAgentID(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	limited := 0
	governed := 0

	for i := 0; i < 160; i++ {
		writeLine(t, client.conn, fmt.Sprintf(`{"type":"govern","call_id":"c-burst-%d","agent_id":"burst-agent","session_id":"s-burst","tool_id":"tool.echo","args":{"n":%d}}`, i, i))
		resp := readJSONWithDeadline(t, client, 500*time.Millisecond)

		if got := asString(resp["error"]); got == "rate_limited" {
			limited++
			if rc := asString(resp["reason_code"]); rc != reasons.SessionRollingLimit {
				t.Fatalf("rate_limited reason_code=%q want %q", rc, reasons.SessionRollingLimit)
			}
			continue
		}

		if effect := asString(resp["effect"]); effect == "" {
			t.Fatalf("expected govern response effect or rate_limited error, got %#v", resp)
		}
		governed++
	}

	if governed == 0 {
		t.Fatalf("expected at least one governed decision before saturation")
	}
	if limited == 0 {
		t.Fatalf("expected burst saturation to trigger rate_limited responses")
	}
}

func TestGovernRateLimitIsolatedByAgentID(t *testing.T) {
	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	client := startSocketHandler(t, srv)
	defer client.conn.Close()

	limited := false
	for i := 0; i < 180; i++ {
		writeLine(t, client.conn, fmt.Sprintf(`{"type":"govern","call_id":"c-agent-a-%d","agent_id":"agent-a","session_id":"s-rate","tool_id":"tool.echo","args":{"n":%d}}`, i, i))
		resp := readJSONWithDeadline(t, client, 500*time.Millisecond)
		if got := asString(resp["error"]); got == "rate_limited" {
			limited = true
			if rc := asString(resp["reason_code"]); rc != reasons.SessionRollingLimit {
				t.Fatalf("agent-a rate_limited reason_code=%q want %q", rc, reasons.SessionRollingLimit)
			}
			break
		}
	}
	if !limited {
		t.Fatalf("expected agent-a burst to reach rate limit")
	}

	// A different agent ID must use an independent limiter bucket.
	writeLine(t, client.conn, `{"type":"govern","call_id":"c-agent-b","agent_id":"agent-b","session_id":"s-rate","tool_id":"tool.echo","args":{"q":"fresh bucket"}}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(resp["error"]); got == "rate_limited" {
		t.Fatalf("unexpected cross-agent throttling: %#v", resp)
	}
	if effect := asString(resp["effect"]); effect == "" {
		t.Fatalf("expected govern decision for agent-b, got %#v", resp)
	}
}

func TestGovernPrincipalTokenVerifiedPermitsPrincipalPolicy(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "sdk-principal"
rules:
  - id: allow-idp-principal
    match:
      tool: "billing/export"
      when: "principal.verified && principal.org == 'acme'"
    effect: permit
default_effect: deny
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{Engine: policy.NewAtomicEngine(engine)})
	srv := NewServer(pipeline, zap.NewNop())
	srv.SetPrincipalResolver(func(ctx context.Context, token string) (*principal.Identity, error) {
		_ = ctx
		if token != "good-token" {
			return nil, errors.New("invalid token")
		}
		return &principal.Identity{ID: "user-123", Org: "acme", Verified: true, Method: "okta_oidc"}, nil
	})

	client := startSocketHandler(t, srv)
	defer client.conn.Close()
	writeLine(t, client.conn, `{"type":"govern","call_id":"c-principal","agent_id":"a-principal","session_id":"s-principal","tool_id":"billing/export","principal_token":"good-token","args":{}}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(resp["effect"]); got != "PERMIT" {
		t.Fatalf("expected PERMIT with verified principal token, got %q (%#v)", got, resp)
	}
}

func TestGovernPrincipalTokenWithoutResolverFailsClosed(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "sdk-principal-fail-closed"
default_effect: permit
rules: []
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	pipeline := core.NewPipeline(core.Config{Engine: policy.NewAtomicEngine(engine)})
	srv := NewServer(pipeline, zap.NewNop())

	client := startSocketHandler(t, srv)
	defer client.conn.Close()
	writeLine(t, client.conn, `{"type":"govern","call_id":"c-principal-fail","agent_id":"a-principal","session_id":"s-principal","tool_id":"billing/export","principal_token":"any-token","args":{}}`)
	resp := readJSONWithDeadline(t, client, 500*time.Millisecond)
	if got := asString(resp["effect"]); got != "DENY" {
		t.Fatalf("expected DENY when principal token is provided without resolver, got %q (%#v)", got, resp)
	}
}

func TestListenRejectsActiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket behavior not available on windows")
	}

	socketPath := filepath.Join(t.TempDir(), "faramesh.sock")
	activeListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unable to allocate unix socket: %v", err)
	}
	defer activeListener.Close()

	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	err = srv.Listen(socketPath)
	if err == nil {
		_ = srv.Close()
		t.Fatal("expected listen to fail when socket is already active")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected already-in-use error, got: %v", err)
	}
}

func TestListenReusesStaleSocketFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket behavior not available on windows")
	}

	socketPath := filepath.Join(t.TempDir(), "faramesh.sock")
	staleListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unable to allocate unix socket: %v", err)
	}
	unixListener, ok := staleListener.(*net.UnixListener)
	if !ok {
		_ = staleListener.Close()
		t.Skip("expected unix listener implementation")
	}
	// Keep the socket inode on disk after Close() so we can exercise stale-socket recovery.
	unixListener.SetUnlinkOnClose(false)
	if err := staleListener.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}
	defer os.Remove(socketPath)
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected stale socket path to remain on disk: %v", err)
	}

	srv := NewServer(core.NewPipeline(core.Config{}), zap.NewNop())
	if err := srv.Listen(socketPath); err != nil {
		t.Fatalf("listen should recover stale socket path: %v", err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("unix", socketPath, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("dial recovered listener: %v", err)
	}
	_ = conn.Close()
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
