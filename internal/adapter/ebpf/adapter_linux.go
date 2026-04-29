//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

type adapter struct {
	log    *zap.Logger
	cfg    Config
	mu     sync.Mutex
	closed bool

	loaded         bool
	attached       bool
	programCount   int
	collection     *ebpf.Collection
	attachedLinks  []link.Link
	attachAttempts int
}

type collectionLoader func(path string) (*ebpf.CollectionSpec, error)

var loadCollectionSpec collectionLoader = ebpf.LoadCollectionSpec

func newAdapter(log *zap.Logger, cfg Config) (Lifecycle, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if strings.TrimSpace(cfg.ObjectPath) == "" {
		return nil, fmt.Errorf("ebpf object path is required")
	}

	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return nil, fmt.Errorf("%w: bpffs not available: %v", ErrUnsupported, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	if err := validateObjectPath(cfg.ObjectPath); err != nil {
		return nil, err
	}

	return &adapter{log: log, cfg: cfg}, nil
}

func (a *adapter) Attach() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fmt.Errorf("ebpf adapter closed")
	}
	if a.attached {
		return nil
	}

	spec, err := loadCollectionSpec(a.cfg.ObjectPath)
	if err != nil {
		return fmt.Errorf("load ebpf object spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("instantiate ebpf collection: %w", err)
	}

	a.collection = coll
	a.programCount = len(coll.Programs)
	a.loaded = true
	a.attached = true
	a.log.Info("ebpf object loaded",
		zap.String("object_path", a.cfg.ObjectPath),
		zap.Int("programs", a.programCount),
		zap.Int("maps", len(coll.Maps)),
	)

	if a.cfg.AttachTracepoints {
		a.attachAttempts++
		if err := a.attachBestEffortTracepointsLocked(); err != nil {
			a.log.Warn("ebpf tracepoint attach failed; continuing with loaded programs",
				zap.Error(err),
				zap.Int("programs_loaded", a.programCount),
			)
		}
	}

	return nil
}

func (a *adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	for _, l := range a.attachedLinks {
		_ = l.Close()
	}
	a.attachedLinks = nil
	if a.collection != nil {
		a.collection.Close()
		a.collection = nil
	}
	a.attached = false
	a.loaded = false
	a.programCount = 0
	a.log.Debug("ebpf adapter closed")
	return nil
}

func (a *adapter) Loaded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loaded
}

func (a *adapter) ProgramCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.programCount
}

func validateObjectPath(path string) error {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return fmt.Errorf("ebpf object path is required")
	}
	st, err := os.Stat(cleaned)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ebpf object path does not exist: %s", cleaned)
		}
		return fmt.Errorf("stat ebpf object path %q: %w", cleaned, err)
	}
	if st.IsDir() {
		return fmt.Errorf("ebpf object path must be a file: %s", cleaned)
	}
	ext := strings.ToLower(filepath.Ext(cleaned))
	if ext != ".o" {
		return fmt.Errorf("ebpf object path must be a .o file: %s", cleaned)
	}
	return nil
}

func (a *adapter) attachBestEffortTracepointsLocked() error {
	if _, err := os.Stat("/sys/kernel/tracing/events"); err != nil {
		return fmt.Errorf("%w: tracepoints unavailable: %v", ErrUnsupported, err)
	}

	var attachedAny bool
	for progName, prog := range a.collection.Programs {
		info, err := prog.Info()
		if err != nil {
			continue
		}
		if info.Type != ebpf.TracePoint {
			continue
		}
		group, name, ok := splitTracepointName(progName)
		if !ok {
			continue
		}
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			continue
		}
		a.attachedLinks = append(a.attachedLinks, l)
		attachedAny = true
	}
	if !attachedAny {
		return fmt.Errorf("%w: no attachable tracepoint programs discovered", ErrUnsupported)
	}
	a.log.Info("ebpf tracepoint programs attached", zap.Int("links", len(a.attachedLinks)))
	return nil
}

func splitTracepointName(progName string) (group string, name string, ok bool) {
	// Accept common naming styles from loaders/generators.
	parts := strings.Split(progName, "/")
	if len(parts) >= 3 && parts[0] == "tracepoint" {
		return parts[1], parts[2], true
	}
	parts = strings.Split(progName, "__")
	if len(parts) >= 3 && parts[0] == "tracepoint" {
		return parts[1], parts[2], true
	}
	return "", "", false
}
