package ebpf

import "testing"

func TestProbeAttachReturnsFallbackWhenConfigured(t *testing.T) {
	p := NewProbe(ProbeConfig{
		FallbackToProxy: true,
		A3ProxyAddr:     "127.0.0.1:7777",
	})

	err := p.Attach()
	if err == nil {
		t.Fatalf("expected Attach to fail closed or return fallback")
	}
	if _, ok := err.(*FallbackError); !ok {
		t.Fatalf("expected fallback error, got %T (%v)", err, err)
	}
	if p.Status().Attached {
		t.Fatalf("probe should not report attached when loader is not implemented")
	}
}
