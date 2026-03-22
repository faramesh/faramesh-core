//go:build !linux

package ebpf

import "go.uber.org/zap"

type unsupportedAdapter struct{}

func newAdapter(_ *zap.Logger, _ Config) (Lifecycle, error) {
	return nil, ErrUnsupported
}

func (unsupportedAdapter) Attach() error { return ErrUnsupported }
func (unsupportedAdapter) Close() error  { return nil }
func (unsupportedAdapter) Loaded() bool  { return false }
func (unsupportedAdapter) ProgramCount() int {
	return 0
}
