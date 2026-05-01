package daemon

import (
	"os"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

// init reads the FARAMESH_USE_JCS environment variable and enables the
// JCS canonicalization toggle for DPR records when set to truthy values.
func init() {
	v := os.Getenv("FARAMESH_USE_JCS")
	// If unset, respect the compiled default. If explicitly set,
	// interpret common truthy/falsey values to override the default.
	if v == "" {
		return
	}
	if v == "1" || v == "true" || v == "TRUE" {
		dpr.UseJCSCanonicalization = true
		return
	}
	// any other explicit value disables JCS (including "0"/"false").
	dpr.UseJCSCanonicalization = false
}
