package governance

import (
	"fmt"
	"io"
	"strings"
)

// Severity classifies a diagnostic.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Diagnostic is a compile-time or check-time issue with CLI formatting (FARAMESH.md §12).
type Diagnostic struct {
	Severity Severity
	Location string
	What     string
	Why      string
	Fix      string
}

func (d Diagnostic) Error() string {
	return d.What
}

// PrintDiagnostics writes diagnostics to w using the standard CLI format.
func PrintDiagnostics(w io.Writer, diags []Diagnostic) {
	for _, d := range diags {
		prefix := "✗"
		if d.Severity == SeverityWarning {
			prefix = "!"
		}
		loc := strings.TrimSpace(d.Location)
		if loc != "" {
			fmt.Fprintf(w, "%s %s — %s\n", prefix, loc, d.What)
		} else {
			fmt.Fprintf(w, "%s %s\n", prefix, d.What)
		}
		if strings.TrimSpace(d.Why) != "" {
			fmt.Fprintf(w, "  %s\n", d.Why)
		}
		if strings.TrimSpace(d.Fix) != "" {
			fmt.Fprintf(w, "  %s\n", d.Fix)
		}
	}
}

// HasErrors reports whether any diagnostic is an error.
func HasErrors(diags []Diagnostic) bool {
	for _, d := range diags {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}
