// Package webhook delivers governance events to configured HTTP endpoints.
// Events are signed with HMAC-SHA256 and delivered asynchronously with retry.
//
// This implements the event delivery component of Layer 9 (Observability Plane).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// EventType identifies the governance event.
type EventType string

const (
	EventDeny           EventType = "deny"
	EventDefer          EventType = "defer"
	EventDeferResolved  EventType = "defer_resolved"
	EventPermit         EventType = "permit"
	EventPolicyReload   EventType = "policy_activated"
	EventKillSwitch     EventType = "kill_switch"
)

const EventSchemaVersionV1 = "1.0"

// Event is the payload sent to webhook endpoints.
type Event struct {
	Version    string    `json:"version"`
	Type       EventType `json:"type"`
	Timestamp  string    `json:"timestamp"`
	AgentID    string    `json:"agent_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	ToolID     string    `json:"tool_id,omitempty"`
	Effect     string    `json:"effect,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	RecordID   string    `json:"record_id,omitempty"`
	Token      string    `json:"defer_token,omitempty"`
}

func (e *Event) normalize() {
	if e.Version == "" {
		e.Version = EventSchemaVersionV1
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
}

func (e Event) Validate() error {
	if e.Version == "" {
		return errors.New("missing required field: version")
	}
	if e.Type == "" {
		return errors.New("missing required field: type")
	}
	if e.Timestamp == "" {
		return errors.New("missing required field: timestamp")
	}
	return nil
}

// Sender delivers webhook events. It is safe for concurrent use.
type Sender struct {
	cfg    policy.WebhookConfig
	client *http.Client
	queue  chan Event
	done   chan struct{}
}

// NewSender creates a webhook sender from policy configuration.
// Starts a background goroutine for async delivery.
func NewSender(cfg policy.WebhookConfig) *Sender {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	s := &Sender{
		cfg: cfg,
		client: &http.Client{Timeout: timeout},
		queue:  make(chan Event, 256),
		done:   make(chan struct{}),
	}
	go s.deliverLoop()
	return s
}

// Send enqueues an event for delivery if the event type is subscribed.
func (s *Sender) Send(evt Event) {
	if !s.subscribedTo(evt.Type) {
		return
	}
	evt.normalize()
	if err := evt.Validate(); err != nil {
		return
	}
	select {
	case s.queue <- evt:
	default:
		// Queue full — drop event silently. The /metrics endpoint
		// tracks delivery failures for alerting.
	}
}

// Close stops the delivery goroutine and drains remaining events.
func (s *Sender) Close() {
	close(s.queue)
	<-s.done
}

func (s *Sender) subscribedTo(eventType EventType) bool {
	for _, e := range s.cfg.Events {
		if EventType(e) == eventType {
			return true
		}
	}
	return false
}

func (s *Sender) deliverLoop() {
	defer close(s.done)
	for evt := range s.queue {
		s.deliver(evt)
	}
}

func (s *Sender) deliver(evt Event) {
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}

	// Sign payload with HMAC-SHA256 if secret is configured.
	var signature string
	if s.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
		mac.Write(body)
		signature = hex.EncodeToString(mac.Sum(nil))
	}

	// Retry up to 3 times with exponential backoff.
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
		if err != nil {
			cancel()
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "faramesh-webhook/1.0")
		if signature != "" {
			req.Header.Set("X-Faramesh-Signature", fmt.Sprintf("sha256=%s", signature))
		}

		resp, err := s.client.Do(req)
		cancel()
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return // success
			}
		}

		// Backoff: 1s, 2s, 4s
		if attempt < maxRetries-1 {
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
		}
	}
}
