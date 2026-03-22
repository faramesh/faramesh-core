// Package reprobuild captures runtime build metadata from debug.ReadBuildInfo for
// supply-chain and reproducible-build checks (CI attestation comparison).
package reprobuild

import (
	"fmt"
	"runtime/debug"
	"sort"
)

// Fingerprint is a JSON-serializable snapshot of the running binary's build metadata.
// Only non-empty fields in an expected fingerprint participate in Compare.
type Fingerprint struct {
	GoVersion   string            `json:"go_version,omitempty"`
	MainPath    string            `json:"main_path,omitempty"`
	MainVersion string            `json:"main_version,omitempty"`
	MainSum     string            `json:"main_sum,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"`
}

// Current reads debug.ReadBuildInfo for this process.
func Current() (*Fingerprint, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf("debug.ReadBuildInfo: not available")
	}
	f := &Fingerprint{
		GoVersion:   bi.GoVersion,
		MainPath:    bi.Main.Path,
		MainVersion: bi.Main.Version,
		MainSum:     bi.Main.Sum,
	}
	if f.MainVersion == "" {
		f.MainVersion = "(devel)"
	}
	settings := make(map[string]string)
	for _, s := range bi.Settings {
		if s.Key == "" {
			continue
		}
		settings[s.Key] = s.Value
	}
	if len(settings) > 0 {
		f.Settings = settings
	}
	return f, nil
}

// Compare returns mismatch descriptions. Fields that are empty in expected are ignored.
// Settings: only keys present in expected.Settings are compared against actual.Settings.
func Compare(expected, actual *Fingerprint) []string {
	if expected == nil {
		return []string{"expected fingerprint is nil"}
	}
	if actual == nil {
		return []string{"actual fingerprint is nil"}
	}
	var diff []string
	if expected.GoVersion != "" && expected.GoVersion != actual.GoVersion {
		diff = append(diff, fmt.Sprintf("go_version: want %q got %q", expected.GoVersion, actual.GoVersion))
	}
	if expected.MainPath != "" && expected.MainPath != actual.MainPath {
		diff = append(diff, fmt.Sprintf("main_path: want %q got %q", expected.MainPath, actual.MainPath))
	}
	if expected.MainVersion != "" && expected.MainVersion != actual.MainVersion {
		diff = append(diff, fmt.Sprintf("main_version: want %q got %q", expected.MainVersion, actual.MainVersion))
	}
	if expected.MainSum != "" && expected.MainSum != actual.MainSum {
		diff = append(diff, fmt.Sprintf("main_sum: want %q got %q", expected.MainSum, actual.MainSum))
	}
	for k, want := range expected.Settings {
		got := ""
		if actual.Settings != nil {
			got = actual.Settings[k]
		}
		if got != want {
			diff = append(diff, fmt.Sprintf("settings[%s]: want %q got %q", k, want, got))
		}
	}
	sort.Strings(diff)
	return diff
}
