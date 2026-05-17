package dpr

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReplayValidatedWithArchives replays archived .bak segments (oldest first) then the active WAL,
// enforcing DPR chain invariants continuously across segment boundaries.
func ReplayValidatedWithArchives(walPath string, fn func(*Record) error) error {
	walPath = strings.TrimSpace(walPath)
	if walPath == "" {
		return fmt.Errorf("empty WAL path")
	}
	archives, err := filepath.Glob(walPath + ".*.bak")
	if err != nil {
		return err
	}
	sort.Strings(archives)
	lastHashByAgent := make(map[string]string)
	for _, seg := range archives {
		if err := replaySegmentValidated(seg, lastHashByAgent, fn); err != nil {
			return fmt.Errorf("archive segment %s: %w", filepath.Base(seg), err)
		}
	}
	if _, err := os.Stat(walPath); err != nil {
		return err
	}
	return replaySegmentValidated(walPath, lastHashByAgent, fn)
}

func replaySegmentValidated(path string, lastHashByAgent map[string]string, fn func(*Record) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for idx := 0; ; idx++ {
		version, payload, err := readNextFramePayload(f)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if version == walVersionControl {
			continue
		}
		if version != walVersion {
			return fmt.Errorf("unknown WAL version %d in %s", version, filepath.Base(path))
		}
		var rec Record
		if err := json.Unmarshal(payload, &rec); err != nil {
			return fmt.Errorf("decode record %d: %w", idx, err)
		}
		if err := validateReplayChainRecord(&rec, lastHashByAgent); err != nil {
			return err
		}
		if err := fn(&rec); err != nil {
			return err
		}
	}
	return nil
}
