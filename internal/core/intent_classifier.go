package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// IntentClassification is a normalized L3 semantic classification output.
// Class should map to the allowlisted intent enum enforced by session/write checks.
type IntentClassification struct {
	Class string
	TTL   time.Duration
}

// IntentClassifier classifies an action asynchronously and returns
// a normalized intent class to persist through the governed session/write path.
type IntentClassifier interface {
	Classify(ctx context.Context, req CanonicalActionRequest, decision Decision) (IntentClassification, error)
}

// HTTPIntentClassifierConfig configures HTTPIntentClassifier.
type HTTPIntentClassifierConfig struct {
	URL         string
	Timeout     time.Duration
	BearerToken string
	Headers     map[string]string
}

// HTTPIntentClassifier calls an external classifier endpoint.
type HTTPIntentClassifier struct {
	url         string
	client      *http.Client
	bearerToken string
	headers     map[string]string
}

// NewHTTPIntentClassifier returns nil when URL is empty.
func NewHTTPIntentClassifier(cfg HTTPIntentClassifierConfig) *HTTPIntentClassifier {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		return nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		headers[k] = v
	}
	return &HTTPIntentClassifier{
		url:         url,
		client:      &http.Client{Timeout: timeout},
		bearerToken: strings.TrimSpace(cfg.BearerToken),
		headers:     headers,
	}
}

type intentClassifierRequest struct {
	CallID         string         `json:"call_id,omitempty"`
	AgentID        string         `json:"agent_id,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	ToolID         string         `json:"tool_id,omitempty"`
	Args           map[string]any `json:"args,omitempty"`
	DecisionEffect string         `json:"decision_effect,omitempty"`
	ReasonCode     string         `json:"reason_code,omitempty"`
	Timestamp      string         `json:"timestamp,omitempty"`
}

type intentClassifierResponse struct {
	IntentClass string `json:"intent_class,omitempty"`
	Class       string `json:"class,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	TTL         string `json:"ttl,omitempty"`
}

// Classify executes the external classifier call and normalizes the response.
func (c *HTTPIntentClassifier) Classify(ctx context.Context, req CanonicalActionRequest, decision Decision) (IntentClassification, error) {
	if c == nil {
		return IntentClassification{}, nil
	}
	payload := intentClassifierRequest{
		CallID:         strings.TrimSpace(req.CallID),
		AgentID:        strings.TrimSpace(req.AgentID),
		SessionID:      strings.TrimSpace(req.SessionID),
		ToolID:         strings.TrimSpace(req.ToolID),
		Args:           req.Args,
		DecisionEffect: string(decision.Effect),
		ReasonCode:     strings.TrimSpace(decision.ReasonCode),
		Timestamp:      req.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return IntentClassification{}, fmt.Errorf("marshal classifier payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return IntentClassification{}, fmt.Errorf("build classifier request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return IntentClassification{}, fmt.Errorf("call classifier endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IntentClassification{}, fmt.Errorf("classifier endpoint returned status %d", resp.StatusCode)
	}

	var decoded intentClassifierResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return IntentClassification{}, fmt.Errorf("decode classifier response: %w", err)
	}

	class := strings.TrimSpace(decoded.IntentClass)
	if class == "" {
		class = strings.TrimSpace(decoded.Class)
	}
	classification := IntentClassification{Class: class}
	if decoded.TTLSeconds > 0 {
		classification.TTL = time.Duration(decoded.TTLSeconds) * time.Second
	} else if strings.TrimSpace(decoded.TTL) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(decoded.TTL)); err == nil && parsed > 0 {
			classification.TTL = parsed
		}
	}
	return classification, nil
}
