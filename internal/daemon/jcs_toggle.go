package daemon

import (
	"os"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

// init reads the FARAMESH_USE_JCS environment variable and enables the
// JCS canonicalization toggle for DPR records when set to truthy values.
func init() {
	v := os.Getenv("FARAMESH_USE_JCS")
	if v == "1" || v == "true" || v == "TRUE" {
		dpr.UseJCSCanonicalization = true
	}
}
