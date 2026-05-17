package fpl

// Agent extension blocks (governance.fms §5).

type RateLimitLine struct {
	Pattern string
	Limit   int64
	Window  string
	Line    int
}

type RedactLine struct {
	Tool  string
	Paths []string
	Line  int
}

type EgressBlock struct {
	Allow []string
	Deny  []string
}

type ModelPolicyBlock struct {
	Allow []string
}

type SessionBlock struct {
	MaxDuration string
	IdleTimeout string
}

type SpawnBlock struct {
	MaxConcurrent int
	AllowedTypes  []string
}

type CompletionGateBlock struct {
	Requires []string
}

type AlertBlock struct {
	On     string
	Notify string
}

type EnforcementBlock struct {
	Fields map[string]ConfigValue
}
