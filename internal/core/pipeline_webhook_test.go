package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/core/webhook"
)

const webhookPolicy = `
faramesh-version: "1.0"
agent-id: "webhook-agent"

rules:
  - id: permit-safe-read
    match:
      tool: "safe/read"
    effect: permit
    reason: "allowed"

default_effect: deny
`

func buildWebhookPipeline(t *testing.T, sender *webhook.Sender) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(webhookPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		Webhooks: sender,
	})
}

func TestWebhookEventValidateRequiredFields(t *testing.T) {
	if err := (webhook.Event{}).Validate(); err == nil {
		t.Fatalf("expected validation error for empty event")
	}
	if err := (webhook.Event{
		Version: webhook.EventSchemaVersionV1,
		Type:    webhook.EventPermit,
	}).Validate(); err == nil {
		t.Fatalf("expected validation error for missing timestamp")
	}
	if err := (webhook.Event{
		Version:   webhook.EventSchemaVersionV1,
		Type:      webhook.EventPermit,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}).Validate(); err != nil {
		t.Fatalf("expected valid event, got error: %v", err)
	}
}

func TestPipelineWebhookPayloadSchemaVersionAndStableKeys(t *testing.T) {
	payloadCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		payloadCh <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := webhook.NewSender(policy.WebhookConfig{
		URL:       srv.URL,
		Events:    []string{string(webhook.EventPermit)},
		TimeoutMs: 500,
	})
	defer sender.Close()

	p := buildWebhookPipeline(t, sender)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "webhook-payload-1",
		AgentID:   "agent-webhook",
		SessionID: "session-webhook",
		ToolID:    "safe/read",
		Args:      map[string]any{"input": "ok"},
		Timestamp: time.Now().UTC(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit decision, got %s (%s)", d.Effect, d.Reason)
	}

	var raw []byte
	select {
	case raw = <-payloadCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for webhook payload")
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal webhook payload: %v", err)
	}

	required := []string{
		"version", "type", "timestamp", "agent_id", "session_id", "tool_id", "effect", "reason_code", "record_id",
	}
	for _, k := range required {
		v, ok := payload[k]
		if !ok {
			t.Fatalf("missing required payload key: %s", k)
		}
		if s, isString := v.(string); isString && s == "" {
			t.Fatalf("required payload key is empty: %s", k)
		}
	}
	if payload["version"] != webhook.EventSchemaVersionV1 {
		t.Fatalf("expected version=%q, got %v", webhook.EventSchemaVersionV1, payload["version"])
	}
	if payload["type"] != string(webhook.EventPermit) {
		t.Fatalf("expected type=%q, got %v", webhook.EventPermit, payload["type"])
	}

	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	expectedKeys := []string{
		"agent_id",
		"effect",
		"reason",
		"reason_code",
		"record_id",
		"rule_id",
		"session_id",
		"timestamp",
		"tool_id",
		"type",
		"version",
	}
	sort.Strings(expectedKeys)
	if len(keys) != len(expectedKeys) {
		t.Fatalf("unexpected webhook key count: got=%v want=%v", keys, expectedKeys)
	}
	for i := range keys {
		if keys[i] != expectedKeys[i] {
			t.Fatalf("unexpected webhook keys: got=%v want=%v", keys, expectedKeys)
		}
	}
}
