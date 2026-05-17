package main

import (
	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func readRecordsFromWAL(path string) ([]*dpr.Record, error) {
	w, err := dpr.OpenWAL(path)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	records := make([]*dpr.Record, 0, 64)
	if err := w.Replay(func(rec *dpr.Record) error {
		records = append(records, rec)
		return nil
	}); err != nil {
		return nil, err
	}
	return records, nil
}
