package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

// Client resolves well-known metadata and kind-aware artifact fetches.
type Client struct {
	Hub *hub.Client
}

// NewClient wraps a hub HTTP client (same base URL as registry).
func NewClient(h *hub.Client) *Client {
	return &Client{Hub: h}
}

// FetchWellKnown loads service discovery document.
func (c *Client) FetchWellKnown(ctx context.Context) (*WellKnown, error) {
	if c == nil || c.Hub == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	base := c.Hub.BaseURL.String()
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+".well-known/faramesh.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Hub.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("well-known: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var wk WellKnown
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return nil, err
	}
	return &wk, nil
}

func (c *Client) fetchRegistryFPL(ctx context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	base := c.Hub.BaseURL.String()
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + ref.APIPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Hub.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry %s: HTTP %d: %s", ref.Kind, resp.StatusCode, string(b))
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := &hub.PackVersionResponse{Name: ref.Name, Version: ref.Version}
	if v, ok := raw["policy_fpl"]; ok {
		_ = json.Unmarshal(v, &out.PolicyFPL)
	}
	if out.PolicyFPL == "" {
		if v, ok := raw["policy_yaml"]; ok {
			_ = json.Unmarshal(v, &out.PolicyYAML)
		}
	}
	if v, ok := raw["sha256_hex"]; ok {
		_ = json.Unmarshal(v, &out.SHA256Hex)
	}
	if v, ok := raw["signature"]; ok && len(v) > 0 && string(v) != "null" {
		var sig hub.PackSignature
		if err := json.Unmarshal(v, &sig); err == nil {
			out.Signature = &sig
		}
	}
	if out.PolicyFPL == "" && out.PolicyYAML == "" {
		return nil, fmt.Errorf("registry %s@%s: empty policy_fpl", ref.Name, ref.Version)
	}
	return out, nil
}

// FetchFPLPack loads policy or framework FPL for compile-time merge.
func (c *Client) FetchFPLPack(ctx context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	if c == nil || c.Hub == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	switch ref.Kind {
	case KindPolicy, KindFramework:
		return c.fetchRegistryFPL(ctx, ref)
	case KindProvider:
		return nil, fmt.Errorf("provider %s@%s is resolved at apply (binary download), not compile merge", ref.Name, ref.Version)
	default:
		return nil, fmt.Errorf("unknown kind %q", ref.Kind)
	}
}
