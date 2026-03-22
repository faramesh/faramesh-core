//go:build !linux

package ebpf

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

func TestNewUnsupported(t *testing.T) {
	_, err := New(zap.NewNop(), Config{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}
