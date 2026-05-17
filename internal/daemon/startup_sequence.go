package daemon

import (
	"fmt"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/governstate"
)

func (d *Daemon) replayWALGovernanceState(wal dpr.Writer) error {
	w, ok := wal.(*dpr.WAL)
	if !ok || w == nil {
		return nil
	}
	gs := governstate.New()
	if err := gs.ReplayFromWAL(w); err != nil {
		return fmt.Errorf("wal budget/rate replay: %w", err)
	}
	return nil
}

func (d *Daemon) verifyDPRChainOnStartup(wal dpr.Writer) error {
	w, ok := wal.(*dpr.WAL)
	if !ok || w == nil {
		return nil
	}
	if err := w.ReplayValidated(func(rec *dpr.Record) error {
		_ = rec
		return nil
	}); err != nil {
		return fmt.Errorf("dpr chain integrity: %w", err)
	}
	if d.log != nil {
		d.log.Info("dpr chain integrity verified")
	}
	return nil
}

func (d *Daemon) haltIfColdStartExceeded() error {
	if d.lifecycle != nil && d.lifecycle.State() == StateHalt {
		return fmt.Errorf("cold_start_deny_window exceeded, halting")
	}
	if d.lifecycle != nil && d.lifecycle.ColdStartExceeded() {
		d.lifecycle.SetState(StateHalt)
		if d.log != nil {
			d.log.Error("cold_start_deny_window exceeded, halting")
		}
		return fmt.Errorf("cold_start_deny_window exceeded, halting")
	}
	return nil
}
