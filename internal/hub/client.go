package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a Hub registry HTTP client (v1 API).
type Client struct {
	BaseURL    *url.URL
	HTTP       *http.Client
	AuthBearer string
}

// NewClient parses baseURL (e.g. https://registry.example.com) and returns a Client.
func NewClient(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("hub base URL is empty (set --hub-url or FARAMESH_HUB_URL)")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse hub URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("hub URL must be http or https")
	}
	if u.Path == "" {
		u.Path = "/"
	} else if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return &Client{
		BaseURL: u,
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

func (c *Client) req(ctx context.Context, method, rel string, body io.Reader) (*http.Request, error) {
	ref, err := url.Parse(rel)
	if err != nil {
		return nil, err
	}
	abs := c.BaseURL.ResolveReference(ref)
	r, err := http.NewRequestWithContext(ctx, method, abs.String(), body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.AuthBearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.AuthBearer)
	}
	return r, nil
}

// Search calls GET /v1/search?q=...
func (c *Client) Search(ctx context.Context, query string) (*SearchResponse, error) {
	q := url.Values{}
	q.Set("q", query)
	r, err := c.req(ctx, http.MethodGet, "v1/search?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hub search: HTTP %d: %s", resp.StatusCode, truncateForErr(b))
	}
	var out SearchResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode search JSON: %w", err)
	}
	return &out, nil
}

// GetPackVersion calls GET /v1/packs/{name}/versions/{version}.
// name uses URL-encoded slash (org%2Fpack).
func (c *Client) GetPackVersion(ctx context.Context, name, version string) (*PackVersionResponse, error) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil, fmt.Errorf("pack name and version are required")
	}
	encName := url.PathEscape(name)
	encVer := url.PathEscape(version)
	rel := fmt.Sprintf("v1/packs/%s/versions/%s", encName, encVer)
	r, err := c.req(ctx, http.MethodGet, rel, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hub get pack: HTTP %d: %s", resp.StatusCode, truncateForErr(b))
	}
	var out PackVersionResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode pack JSON: %w", err)
	}
	return &out, nil
}

// Publish posts JSON to /v1/packs (optional on registry implementations).
func (c *Client) Publish(ctx context.Context, req PublishRequest) error {
	if req.APIVersion == "" {
		req.APIVersion = APIVersion
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := c.req(ctx, http.MethodPost, "v1/packs", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hub publish: HTTP %d: %s", resp.StatusCode, truncateForErr(b))
	}
	return nil
}

func truncateForErr(b []byte) string {
	const max = 512
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

// ValidatePackPayload checks sha256 and optionally signature.
func ValidatePackPayload(p *PackVersionResponse) error {
	if p == nil {
		return fmt.Errorf("nil pack response")
	}
	body := []byte(p.PolicyYAML)
	got := Sum256Hex(body)
	want := strings.ToLower(strings.TrimSpace(p.SHA256Hex))
	if want != "" && got != want {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	if p.Signature != nil {
		if err := VerifyPolicySignature(body, p.Signature); err != nil {
			return fmt.Errorf("signature: %w", err)
		}
	}
	return nil
}
