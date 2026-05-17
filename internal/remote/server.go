package remote

import (
	"encoding/json"
	"net/http"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Handler serves POST /v1/evaluate for remote governance (Lambda/Cloud Run).
type Handler struct {
	Pipeline *core.Pipeline
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h == nil || h.Pipeline == nil {
		http.Error(w, "governance unavailable", http.StatusServiceUnavailable)
		return
	}
	var req core.CanonicalActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	decision := h.Pipeline.Evaluate(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// Register mounts remote governance routes on mux.
func Register(mux *http.ServeMux, p *core.Pipeline) {
	if mux == nil || p == nil {
		return
	}
	mux.Handle("/v1/evaluate", &Handler{Pipeline: p})
}
