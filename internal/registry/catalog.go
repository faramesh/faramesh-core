package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Search calls GET /v1/search on an HTTP registry.
func (c *Client) Search(ctx context.Context, q, kind, tier string) ([]CatalogRow, error) {
	if c == nil || c.Hub == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	base := c.Hub.BaseURL.String()
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + "v1/search?"
	params := []string{}
	if strings.TrimSpace(q) != "" {
		params = append(params, "q="+strings.TrimSpace(q))
	}
	if strings.TrimSpace(kind) != "" {
		params = append(params, "kind="+strings.TrimSpace(kind))
	}
	if strings.TrimSpace(tier) != "" {
		params = append(params, "tier="+strings.TrimSpace(tier))
	}
	url += strings.Join(params, "&")

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
		return nil, fmt.Errorf("registry search: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var payload struct {
		Results []struct {
			Kind          string `json:"kind"`
			Name          string `json:"name"`
			LatestVersion string `json:"latest_version"`
			Description   string `json:"description"`
			TrustTier     string `json:"trust_tier"`
			Category      string `json:"category"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := make([]CatalogRow, 0, len(payload.Results))
	for _, r := range payload.Results {
		out = append(out, CatalogRow{
			Kind: r.Kind, Name: r.Name, LatestVersion: r.LatestVersion,
			Description: r.Description, TrustTier: r.TrustTier, Category: r.Category,
		})
	}
	return out, nil
}

// Search filters the local catalog index.
func (l *LocalCatalog) Search(q, kind, tier string) ([]CatalogRow, error) {
	idx, err := l.loadIndex()
	if err != nil {
		return nil, err
	}
	return filterCatalogRows(idx, strings.ToLower(strings.TrimSpace(q)), strings.ToLower(strings.TrimSpace(kind)), strings.ToLower(strings.TrimSpace(tier))), nil
}
