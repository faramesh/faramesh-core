package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/delegate"
)

// delegationEntryDTO mirrors the CLI's delegationEntry shape so the wire
// format stays stable regardless of internal Grant evolution.
type delegationEntryDTO struct {
	Token      string `json:"token"`
	FromAgent  string `json:"from_agent"`
	ToAgent    string `json:"to_agent"`
	Scope      string `json:"scope"`
	ExpiresAt  string `json:"expires_at"`
	Ceiling    string `json:"ceiling,omitempty"`
	Active     bool   `json:"active"`
	CreatedAt  string `json:"created_at"`
	ChainDepth int    `json:"chain_depth"`
}

func entryFromGrant(g delegate.Grant) delegationEntryDTO {
	return delegationEntryDTO{
		Token:      g.Token,
		FromAgent:  g.FromAgent,
		ToAgent:    g.ToAgent,
		Scope:      g.Scope,
		ExpiresAt:  g.ExpiresAt.UTC().Format(time.RFC3339),
		Ceiling:    g.Ceiling,
		Active:     g.Active,
		CreatedAt:  g.IssuedAt.UTC().Format(time.RFC3339),
		ChainDepth: g.ChainDepth,
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (d *Daemon) handleDelegateGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	var req delegate.GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode: %v", err))
		return
	}
	g, err := d.delegate.Grant(req)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, delegate.ErrChainTooDeep), errors.Is(err, delegate.ErrScopeNotSubset):
			status = http.StatusForbidden
		case errors.Is(err, delegate.ErrInvalidRequest):
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	resp := struct {
		Token     string `json:"token"`
		FromAgent string `json:"from_agent"`
		ToAgent   string `json:"to_agent"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
		Ceiling   string `json:"ceiling,omitempty"`
	}{
		Token:     g.Token,
		FromAgent: g.FromAgent,
		ToAgent:   g.ToAgent,
		Scope:     g.Scope,
		ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
		Ceiling:   g.Ceiling,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Daemon) handleDelegateList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query parameter required")
		return
	}
	grants := d.delegate.List(agentID)
	out := make([]delegationEntryDTO, 0, len(grants))
	for _, g := range grants {
		out = append(out, entryFromGrant(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"delegations": out})
}

func (d *Daemon) handleDelegateRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	var req struct {
		FromAgent string `json:"from_agent"`
		ToAgent   string `json:"to_agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode: %v", err))
		return
	}
	n, err := d.delegate.Revoke(req.FromAgent, req.ToAgent)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		Revoked bool   `json:"revoked"`
		Message string `json:"message"`
	}{Revoked: n > 0}
	if n == 0 {
		resp.Message = "no active delegations found"
	} else {
		resp.Message = fmt.Sprintf("revoked %d delegation(s)", n)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Daemon) handleDelegateInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token query parameter required")
		return
	}
	g, ok := d.delegate.Inspect(token)
	if !ok {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	writeJSON(w, http.StatusOK, entryFromGrant(g))
}

func (d *Daemon) handleDelegateVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode: %v", err))
		return
	}
	res := d.delegate.Verify(req.Token)
	resp := struct {
		Valid      bool   `json:"valid"`
		Reason     string `json:"reason,omitempty"`
		Scope      string `json:"scope,omitempty"`
		ExpiresAt  string `json:"expires_at,omitempty"`
		ChainDepth int    `json:"chain_depth,omitempty"`
	}{
		Valid:      res.Valid,
		Reason:     res.Reason,
		Scope:      res.Scope,
		ChainDepth: res.ChainDepth,
	}
	if !res.ExpiresAt.IsZero() {
		resp.ExpiresAt = res.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Daemon) handleDelegateChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if d.delegate == nil {
		writeError(w, http.StatusServiceUnavailable, "delegation service not initialised")
		return
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query parameter required")
		return
	}
	chain := d.delegate.Chain(agentID)
	type linkDTO struct {
		FromAgent string `json:"from_agent"`
		ToAgent   string `json:"to_agent"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
		Depth     int    `json:"depth"`
	}
	out := make([]linkDTO, 0, len(chain))
	for _, g := range chain {
		out = append(out, linkDTO{
			FromAgent: g.FromAgent,
			ToAgent:   g.ToAgent,
			Scope:     g.Scope,
			ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
			Depth:     g.ChainDepth,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": agentID, "chain": out})
}

// registerDelegateRoutes attaches the six /api/v1/delegate/* handlers to mux.
func (d *Daemon) registerDelegateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/delegate/grant", d.handleDelegateGrant)
	mux.HandleFunc("/api/v1/delegate/list", d.handleDelegateList)
	mux.HandleFunc("/api/v1/delegate/revoke", d.handleDelegateRevoke)
	mux.HandleFunc("/api/v1/delegate/inspect", d.handleDelegateInspect)
	mux.HandleFunc("/api/v1/delegate/verify", d.handleDelegateVerify)
	mux.HandleFunc("/api/v1/delegate/chain", d.handleDelegateChain)
}
