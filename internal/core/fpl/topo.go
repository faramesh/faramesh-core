package fpl

// TopoKind classifies topology statements parsed from FPL manifest lines.
type TopoKind int

const (
	TopoOrchestrator TopoKind = iota
	TopoAllow
)

// TopoStatement is a single manifest line after parse (decl or allow).
type TopoStatement struct {
	Kind TopoKind

	// Orchestrator declaration (manifest orchestrator … undeclared …)
	OrchID           string
	UndeclaredPolicy string

	// Allow line (manifest allow … agent …)
	AllowOrchID      string
	TargetAgentID    string
	MaxPerSession    int // 0 = unlimited / unset
	RequiresApproval bool
}
