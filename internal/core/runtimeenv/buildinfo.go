package runtimeenv

import (
	"runtime/debug"
	"strings"
)

// BinaryVersion returns the embedded Go module version for policy when: vars.faramesh_version.
// In development builds this is often "(devel)" or empty — surfaced as "dev".
func BinaryVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := strings.TrimSpace(bi.Main.Version)
	switch v {
	case "", "(devel)":
		return "dev"
	default:
		return v
	}
}
