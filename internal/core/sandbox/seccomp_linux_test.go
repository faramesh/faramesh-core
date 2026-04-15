//go:build linux

package sandbox

import "testing"

func TestBuildBPFFilterStartsWithAuditArchValidation(t *testing.T) {
	filter := buildBPFFilter(map[uint32]bool{1: true})
	if len(filter) < 4 {
		t.Fatalf("expected at least 4 instructions, got %d", len(filter))
	}
	if filter[0].Code != 0x20 || filter[0].K != seccompDataArchOffset {
		t.Fatalf("first instruction = %#v, want load arch from offset %d", filter[0], seccompDataArchOffset)
	}
	if filter[1].Code != 0x15 || filter[1].K != currentAuditArch() {
		t.Fatalf("second instruction = %#v, want JEQ on audit arch %#x", filter[1], currentAuditArch())
	}
	if filter[2].Code != 0x06 {
		t.Fatalf("third instruction = %#v, want RET deny", filter[2])
	}
	if filter[3].Code != 0x20 || filter[3].K != seccompDataNrOffset {
		t.Fatalf("fourth instruction = %#v, want load syscall nr", filter[3])
	}
}
