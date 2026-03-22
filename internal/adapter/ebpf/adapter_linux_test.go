//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

func TestAdapterLifecycle(t *testing.T) {
	origLoader := loadCollectionSpec
	t.Cleanup(func() { loadCollectionSpec = origLoader })

	loadCollectionSpec = func(_ string) (*ebpf.CollectionSpec, error) {
		return &ebpf.CollectionSpec{}, nil
	}

	a := &adapter{
		log: zap.NewNop(),
		cfg: Config{ObjectPath: "/tmp/test.o"},
	}
	if err := a.Attach(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := a.Attach(); err != nil {
		t.Fatalf("attach idempotent: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close idempotent: %v", err)
	}
	if err := a.Attach(); err == nil {
		t.Fatalf("expected attach to fail after close")
	}
}

func TestNewAdapterMissingObjectPath(t *testing.T) {
	if _, err := newAdapter(zap.NewNop(), Config{}); err == nil {
		t.Fatalf("expected error for missing object path")
	}
}

func TestNewAdapterInvalidObjectFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-object.txt")
	if err := os.WriteFile(path, []byte("bad"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := newAdapter(zap.NewNop(), Config{ObjectPath: path}); err == nil {
		t.Fatalf("expected invalid object file extension error")
	}
}

func TestAttachInvalidObjectContents(t *testing.T) {
	origLoader := loadCollectionSpec
	t.Cleanup(func() { loadCollectionSpec = origLoader })

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.o")
	if err := os.WriteFile(path, []byte("not-elf"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	loadCollectionSpec = ebpf.LoadCollectionSpec

	a := &adapter{
		log: zap.NewNop(),
		cfg: Config{ObjectPath: path},
	}
	if err := a.Attach(); err == nil {
		t.Fatalf("expected attach to fail for invalid object")
	}
}

func TestAdapterLoadedStateTransitions(t *testing.T) {
	origLoader := loadCollectionSpec
	t.Cleanup(func() { loadCollectionSpec = origLoader })

	loadCollectionSpec = func(_ string) (*ebpf.CollectionSpec, error) {
		return &ebpf.CollectionSpec{}, nil
	}

	a := &adapter{
		log: zap.NewNop(),
		cfg: Config{ObjectPath: "/tmp/test.o"},
	}

	if a.Loaded() {
		t.Fatalf("expected unloaded before attach")
	}
	if a.ProgramCount() != 0 {
		t.Fatalf("expected zero programs before attach")
	}
	if err := a.Attach(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if !a.Loaded() {
		t.Fatalf("expected loaded after attach")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if a.Loaded() {
		t.Fatalf("expected unloaded after close")
	}
}
