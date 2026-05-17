// Package remote provides HTTPS governance transport for Lambda/Cloud Run (FARAMESH.md §21).
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Client calls a remote Faramesh governance API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Token:      token,
	}
}

// Evaluate sends a CAR to the remote governance endpoint.
func (c *Client) Evaluate(ctx context.Context, req core.CanonicalActionRequest) (core.Decision, error) {
	if c == nil || c.BaseURL == "" {
		return core.Decision{}, fmt.Errorf("remote client not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return core.Decision{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return core.Decision{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return core.Decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return core.Decision{}, fmt.Errorf("remote evaluate: HTTP %d", resp.StatusCode)
	}
	var decision core.Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return core.Decision{}, err
	}
	return decision, nil
}
