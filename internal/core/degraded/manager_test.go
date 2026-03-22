package degraded

import "testing"

func TestManagerCurrentTransitions(t *testing.T) {
	m := NewManager()
	if got := m.Current(); got != ModeFull {
		t.Fatalf("expected FULL default mode, got %s", got)
	}

	m.SetDegraded(true)
	if got := m.Current(); got != ModeStateless {
		t.Fatalf("expected STATELESS in forced degraded mode, got %s", got)
	}

	m.SetFault(true)
	if got := m.Current(); got != ModeEmergency {
		t.Fatalf("expected EMERGENCY in fault mode, got %s", got)
	}

	m.SetFault(false)
	m.SetDegraded(false)
	m.SetBackendStatus(false, false)
	if got := m.Current(); got != ModeEmergency {
		t.Fatalf("expected EMERGENCY with both backends unavailable, got %s", got)
	}
}
