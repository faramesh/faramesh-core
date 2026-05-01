package observe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetrics_ObserveSemanticDriftAndExposeMetrics(t *testing.T) {
	m := NewMetrics()
	if err := m.ObserveSemanticDrift(SemanticDriftObservation{
		ProviderID: "mock-provider",
		SessionID:  "sess-1",
		Distance:   0.8,
		Threshold:  0.5,
		Triggered:  true,
		Denied:     true,
		Timestamp:  time.Now(),
	}); err != nil {
		t.Fatalf("ObserveSemanticDrift error: %v", err)
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "faramesh_semantic_drift_total{status=\"observed\"} 1") {
		t.Fatalf("missing observed counter in metrics:\n%s", body)
	}
	if !strings.Contains(body, "faramesh_semantic_drift_total{status=\"triggered\"} 1") {
		t.Fatalf("missing triggered counter in metrics:\n%s", body)
	}
	if !strings.Contains(body, "faramesh_semantic_drift_total{status=\"denied\"} 1") {
		t.Fatalf("missing denied counter in metrics:\n%s", body)
	}
	if !strings.Contains(body, "faramesh_semantic_drift_by_provider_total{provider=\"mock-provider\"} 1") {
		t.Fatalf("missing provider counter in metrics:\n%s", body)
	}
}
