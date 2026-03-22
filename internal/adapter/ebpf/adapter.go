package ebpf

import (
	"errors"

	"go.uber.org/zap"
)

// ErrUnsupported indicates the current platform/runtime cannot bootstrap eBPF safely.
var ErrUnsupported = errors.New("ebpf unsupported")

// Lifecycle defines a minimal eBPF adapter runtime lifecycle.
type Lifecycle interface {
	Attach() error
	Close() error
	Loaded() bool
	ProgramCount() int
}

// Config configures Linux eBPF adapter behavior.
type Config struct {
	// ObjectPath points to a compiled eBPF ELF object file.
	ObjectPath string
	// AttachTracepoints attempts a best-effort tracepoint attach when possible.
	AttachTracepoints bool
}

// New constructs an eBPF adapter for the current platform.
func New(log *zap.Logger, cfg Config) (Lifecycle, error) {
	return newAdapter(log, cfg)
}
