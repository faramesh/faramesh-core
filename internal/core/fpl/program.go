package fpl

// CompileDocument compiles a full structured FPL document into a DocumentIR
// suitable for conversion to policy.Doc.
func CompileDocument(doc *Document) (*DocumentIR, error) {
	ir := &DocumentIR{}

	for _, sys := range doc.Systems {
		ir.Version = sys.Version
		ir.OnPolicyLoadFailure = sys.OnPolicyLoadFailure
		ir.MaxOutputBytes = sys.MaxOutputBytes
	}

	for _, ag := range doc.Agents {
		air, err := compileAgent(ag)
		if err != nil {
			return nil, err
		}
		ir.Agents = append(ir.Agents, air)
	}

	// Compile flat rules at top level.
	for _, r := range doc.FlatRules {
		cr, err := CompileRule(r)
		if err != nil {
			return nil, err
		}
		ir.FlatRules = append(ir.FlatRules, cr)
	}

	ir.Topo = doc.Topo
	return ir, nil
}

func compileAgent(ag *AgentBlock) (*AgentIR, error) {
	air := &AgentIR{
		ID:        ag.ID,
		Default:   ag.Default,
		Model:     ag.Model,
		Framework: ag.Framework,
		Version:   ag.Version,
		Vars:      ag.Vars,
	}

	for _, b := range ag.Budgets {
		air.Budgets = append(air.Budgets, &BudgetIR{
			ID:       b.ID,
			Max:      b.Max,
			Daily:    b.Daily,
			MaxCalls: b.MaxCalls,
			OnExceed: b.OnExceed,
		})
	}

	for _, ph := range ag.Phases {
		pir := &PhaseIR{ID: ph.ID, Tools: ph.Tools, Duration: ph.Duration, Next: ph.Next}
		for _, r := range ph.Rules {
			cr, err := CompileRule(r)
			if err != nil {
				return nil, err
			}
			pir.Rules = append(pir.Rules, cr)
		}
		air.Phases = append(air.Phases, pir)
	}

	for _, r := range ag.Rules {
		cr, err := CompileRule(r)
		if err != nil {
			return nil, err
		}
		air.Rules = append(air.Rules, cr)
	}

	for _, d := range ag.Delegates {
		air.Delegates = append(air.Delegates, &DelegateIR{
			Target:  d.TargetAgent,
			Scope:   d.Scope,
			TTL:     d.TTL,
			Ceiling: d.Ceiling,
		})
	}

	for _, a := range ag.Ambients {
		air.Ambients = append(air.Ambients, &AmbientIR{
			Limits:   a.Limits,
			OnExceed: a.OnExceed,
		})
	}

	for _, s := range ag.Selectors {
		air.Selectors = append(air.Selectors, &SelectorIR{
			ID:            s.ID,
			Source:        s.Source,
			Cache:         s.Cache,
			OnUnavailable: s.OnUnavailable,
			OnTimeout:     s.OnTimeout,
		})
	}

	for _, c := range ag.Credentials {
		air.Credentials = append(air.Credentials, &CredentialIR{
			ID:       c.ID,
			Scope:    c.Scope,
			MaxScope: c.MaxScope,
		})
	}

	return air, nil
}

// ── IR Types ───────────────────────────────────────────────────────────────

// DocumentIR is the compiled intermediate representation of an FPL document.
type DocumentIR struct {
	Version              string
	OnPolicyLoadFailure  string
	MaxOutputBytes       int
	Agents               []*AgentIR
	FlatRules            []*CompiledRule
	Topo                 []TopoStatement
}

type AgentIR struct {
	ID          string
	Default     string
	Model       string
	Framework   string
	Version     string
	Vars        map[string]string
	Budgets     []*BudgetIR
	Phases      []*PhaseIR
	Rules       []*CompiledRule
	Delegates   []*DelegateIR
	Ambients    []*AmbientIR
	Selectors   []*SelectorIR
	Credentials []*CredentialIR
}

type BudgetIR struct {
	ID       string
	Max      float64
	Daily    float64
	MaxCalls int64
	OnExceed string
}

type PhaseIR struct {
	ID       string
	Tools    []string
	Duration string
	Next     string
	Rules    []*CompiledRule
}

type DelegateIR struct {
	Target  string
	Scope   string
	TTL     string
	Ceiling string
}

type AmbientIR struct {
	Limits   map[string]string
	OnExceed string
}

type SelectorIR struct {
	ID            string
	Source        string
	Cache         string
	OnUnavailable string
	OnTimeout     string
}

type CredentialIR struct {
	ID       string
	Scope    []string
	MaxScope string
}
