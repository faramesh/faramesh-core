package observe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_DPRAsyncSeriesInPrometheusHandler(t *testing.T) {
	m := NewMetrics()
	m.RecordDPREnqueue(true)
	m.RecordDPREnqueue(false)
	m.RecordDPRAsyncPersist(true)
	m.RecordDPRAsyncPersist(false)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, sub := range []string{
		`faramesh_dpr_async_enqueue_total{status="success"}`,
		`faramesh_dpr_async_enqueue_total{status="error"}`,
		`faramesh_dpr_async_persist_total{status="success"}`,
		`faramesh_dpr_async_persist_total{status="error"}`,
	} {
		if !strings.Contains(body, sub) {
			t.Fatalf("missing %q in:\n%s", sub, body)
		}
	}
}
