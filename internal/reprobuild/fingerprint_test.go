package reprobuild

import (
	"encoding/json"
	"testing"
)

func TestCurrent(t *testing.T) {
	fp, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if fp.GoVersion == "" {
		t.Fatal("expected go_version")
	}
	if fp.MainPath == "" {
		// debug.ReadBuildInfo returns an empty Main.Path when running under
		// 'go test' without a fully-linked binary. Skip rather than fail so
		// the test remains useful when run against a real built binary.
		t.Skip("skipping: debug.ReadBuildInfo has no main_path in test binary")
	}
	b, err := json.Marshal(fp)
	if err != nil {
		t.Fatal(err)
	}
	var round Fingerprint
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.GoVersion != fp.GoVersion || round.MainPath != fp.MainPath {
		t.Fatalf("round trip: %+v vs %+v", fp, round)
	}
}

func TestCompare_partialExpected(t *testing.T) {
	exp := &Fingerprint{MainPath: "github.com/faramesh/faramesh-core"}
	act := &Fingerprint{MainPath: "github.com/faramesh/faramesh-core", GoVersion: "go1.25.0"}
	if d := Compare(exp, act); len(d) != 0 {
		t.Fatalf("unexpected diff: %v", d)
	}
}

func TestCompare_mismatch(t *testing.T) {
	exp := &Fingerprint{GoVersion: "go1.0.0"}
	act := &Fingerprint{GoVersion: "go1.25.0"}
	d := Compare(exp, act)
	if len(d) != 1 || d[0] == "" {
		t.Fatalf("expected one diff, got %v", d)
	}
}

func TestCompare_settingsSubset(t *testing.T) {
	exp := &Fingerprint{
		Settings: map[string]string{"GOARCH": "arm64"},
	}
	act := &Fingerprint{
		Settings: map[string]string{"GOARCH": "amd64", "GOOS": "linux"},
	}
	d := Compare(exp, act)
	if len(d) != 1 {
		t.Fatalf("want 1 diff, got %v", d)
	}
}
