package observe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_NetworkHardeningSeriesInPrometheusHandler(t *testing.T) {
	m := NewMetrics()
	m.RecordHardeningOutcome("enforce", "deny", "NETWORK_SSRF_BLOCK")
	m.RecordHardeningOutcome("audit", "audit_violation", "NETWORK_SSRF_BLOCK")
	m.RecordHardeningOutcome("audit", "audit_bypass", "NETWORK_L7_AUDIT_VIOLATION")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, sub := range []string{
		`faramesh_network_hardening_total{mode="enforce",outcome="deny",reason_code="NETWORK_SSRF_BLOCK"}`,
		`faramesh_network_hardening_total{mode="audit",outcome="audit_violation",reason_code="NETWORK_SSRF_BLOCK"}`,
		`faramesh_network_hardening_total{mode="audit",outcome="audit_bypass",reason_code="NETWORK_L7_AUDIT_VIOLATION"}`,
	} {
		if !strings.Contains(body, sub) {
			t.Fatalf("missing %q in:\n%s", sub, body)
		}
	}
}
