package governance

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/provider"
)

// CheckOptions configures static validation.
type CheckOptions struct {
	// RequireEnv fails when env("VAR") or ${VAR} references are unset.
	RequireEnv bool
}

// Check performs static validation on a governance document.
func Check(doc *ast.Document, opts CheckOptions) []Diagnostic {
	if doc == nil {
		return []Diagnostic{{
			Severity: SeverityError,
			What:     "empty governance document",
			Why:      "No stack configuration was parsed.",
			Fix:      "Add a governance.fms file with at least one agent block.",
		}}
	}
	var diags []Diagnostic
	loc := doc.SourcePath
	if loc == "" {
		loc = "governance.fms"
	}

	for _, imp := range doc.Imports {
		if strings.HasSuffix(strings.ToLower(imp.Ref), "@latest") {
			line := imp.Line
			if line == 0 {
				line = 1
			}
			diags = append(diags, Diagnostic{
				Severity: SeverityError,
				Location: fmt.Sprintf("%s:%d", loc, line),
				What:     fmt.Sprintf("import %q uses @latest", imp.Ref),
				Why:      "Registry imports must pin an explicit semver version.",
				Fix:      "Change the import to a fixed version, e.g. @1.0.0.",
			})
		}
	}

	providerNames := make(map[string]struct{}, len(doc.Providers))
	for name, p := range doc.Providers {
		providerNames[name] = struct{}{}
		diags = append(diags, checkProviderConfig(loc, name, p, opts)...)
	}

	for name, id := range doc.Identities {
		diags = append(diags, checkIdentityConfig(loc, name, id, opts)...)
	}

	if len(doc.Agents) == 0 && len(doc.FlatRules) == 0 {
		diags = append(diags, Diagnostic{
			Severity: SeverityError,
			Location: loc,
			What:     "no agents declared",
			Why:      "A stack must declare at least one agent with policy rules.",
			Fix:      `Add agent "<name>" { rules { ... } } to the governance file.`,
		})
	}

	if doc.Trust != nil {
		diags = append(diags, checkTrustCycles(loc, doc.Trust)...)
	}

	if len(doc.Agents) > 1 {
		diags = append(diags, Diagnostic{
			Severity: SeverityWarning,
			Location: loc,
			What:     fmt.Sprintf("multiple agents (%d) — runtime loads the first agent only", len(doc.Agents)),
			Why:      "The daemon currently materializes a single-agent policy file.",
			Fix:      "Use one primary agent per stack until multi-agent runtime support ships.",
		})
	}

	for agentName, ag := range doc.Agents {
		for _, cred := range ag.Credentials {
			backend := strings.TrimSpace(cred.Backend)
			if backend == "" {
				continue
			}
			if _, ok := providerNames[backend]; !ok {
				diags = append(diags, Diagnostic{
					Severity: SeverityError,
					Location: fmt.Sprintf("%s — credential %q", loc, cred.Name),
					What:     fmt.Sprintf(`credential "%s" specifies backend "%s"`, cred.Name, backend),
					Why:      fmt.Sprintf("No provider named %q is declared in this stack.", backend),
					Fix: fmt.Sprintf(`Add a provider block before this agent block:

    provider "%s" {
      type  = "<provider-type>"
    }`, backend),
				})
			}
		}
		diags = append(diags, checkDenyBangConflicts(loc, agentName, ag.Rules)...)
	}

	if doc.Runtime != nil {
		diags = append(diags, checkRuntimeEnv(loc, doc.Runtime, opts)...)
	}

	if len(doc.Providers) > 0 {
		specs := providerSpecsFromAST(doc)
		pdiags := CheckProviders(context.Background(), "", specs, loc)
		diags = append(diags, pdiags...)
	}

	return diags
}

func providerSpecsFromAST(doc *ast.Document) []provider.Spec {
	if doc == nil {
		return nil
	}
	specs := make([]provider.Spec, 0, len(doc.Providers))
	for name, p := range doc.Providers {
		specs = append(specs, provider.Spec{
			Name:   name,
			Type:   p.Type,
			Source: p.Source,
			Config: providerConfigMapResolved(p),
		})
	}
	return specs
}

func checkProviderConfig(loc, name string, p *ast.Provider, opts CheckOptions) []Diagnostic {
	if p == nil {
		return nil
	}
	var diags []Diagnostic
	ref := fmt.Sprintf("%s — provider %q", loc, name)
	for key, val := range p.Config {
		diags = append(diags, checkValueSecret(ref, key, val)...)
		if opts.RequireEnv {
			if d, ok := checkEnvSet(ref, key, val); !ok {
				diags = append(diags, d)
			}
		}
	}
	for _, key := range []string{"addr", "token", "dsn"} {
		if v, ok := p.Config[key]; ok && opts.RequireEnv {
			if d, ok := checkEnvSet(ref, key, v); !ok {
				diags = append(diags, d)
			}
		}
	}
	return diags
}

func checkIdentityConfig(loc, name string, id *ast.Identity, opts CheckOptions) []Diagnostic {
	if id == nil {
		return nil
	}
	var diags []Diagnostic
	ref := fmt.Sprintf("%s — identity %q", loc, name)
	for key, val := range id.Config {
		diags = append(diags, checkValueSecret(ref, key, val)...)
		if opts.RequireEnv {
			if d, ok := checkEnvSet(ref, key, val); !ok {
				diags = append(diags, d)
			}
		}
	}
	return diags
}

func checkRuntimeEnv(loc string, rt *ast.Runtime, opts CheckOptions) []Diagnostic {
	if !opts.RequireEnv || rt == nil {
		return nil
	}
	var diags []Diagnostic
	for key, val := range rt.Extra {
		if d, ok := checkEnvString(loc, key, val); !ok {
			diags = append(diags, d)
		}
	}
	if strings.Contains(rt.DSN, "env(") {
		// already expanded in compile; skip
	}
	return diags
}

func checkValueSecret(ref, key string, v ast.Value) []Diagnostic {
	if v.Kind != ast.ValueString {
		return nil
	}
	s := strings.TrimSpace(v.String)
	if s == "" {
		return nil
	}
	lowerKey := strings.ToLower(key)
	if strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "token") ||
		strings.Contains(lowerKey, "password") || lowerKey == "key" {
		return []Diagnostic{{
			Severity: SeverityError,
			Location: ref,
			What:     fmt.Sprintf("inline secret in field %q", key),
			Why:      "Provider and runtime config must reference secrets via env() or ${VAR}, not string literals.",
			Fix:      fmt.Sprintf("Replace the literal with env(\"%s\") or ${%s}.", strings.ToUpper(key), strings.ToUpper(key)),
		}}
	}
	return nil
}

func checkEnvSet(ref, key string, v ast.Value) (Diagnostic, bool) {
	if v.Kind != ast.ValueEnv {
		return Diagnostic{}, true
	}
	name := strings.TrimSpace(v.EnvVar)
	if name == "" {
		return Diagnostic{}, true
	}
	if os.Getenv(name) != "" {
		return Diagnostic{}, true
	}
	loc := ref
	if strings.Contains(ref, "governance") {
		// prefer file:line style when we only have file path
		loc = strings.Split(ref, " — ")[0]
	}
	return Diagnostic{
		Severity: SeverityError,
		Location: loc,
		What:     fmt.Sprintf("env(%q) is not set", name),
		Why:      "This variable must be set before faramesh apply runs.",
		Fix:      fmt.Sprintf("Set it in your shell: export %s=<value>", name),
	}, false
}

func checkEnvString(loc, key, val string) (Diagnostic, bool) {
	if !strings.HasPrefix(val, "env(") {
		return Diagnostic{}, true
	}
	// extract VAR from env("VAR") display form
	start := strings.Index(val, `"`)
	end := strings.LastIndex(val, `"`)
	if start < 0 || end <= start {
		return Diagnostic{}, true
	}
	name := val[start+1 : end]
	if os.Getenv(name) != "" {
		return Diagnostic{}, true
	}
	return Diagnostic{
		Severity: SeverityError,
		Location: loc,
		What:     fmt.Sprintf("env(%q) is not set", name),
		Why:      "This variable must be set before faramesh apply runs.",
		Fix:      fmt.Sprintf("Set it in your shell: export %s=<value>", name),
	}, false
}

func checkDenyBangConflicts(loc, agentName string, rules []ast.Rule) []Diagnostic {
	var diags []Diagnostic
	denyTools := make(map[string]int)
	for i, r := range rules {
		if r.Effect == "deny!" {
			denyTools[r.Tool] = i + 1
		}
	}
	for i, r := range rules {
		if r.Effect != "permit" && r.Effect != "allow" && r.Effect != "approve" {
			continue
		}
		if line, ok := denyTools[r.Tool]; ok {
			diags = append(diags, Diagnostic{
				Severity: SeverityError,
				Location: fmt.Sprintf("%s — agent %q", loc, agentName),
				What:     fmt.Sprintf("deny! %s conflicts with %s %s at line %d", r.Tool, r.Effect, r.Tool, i+1),
				Why:      "deny! is unconditional and cannot be overridden by a downstream permit in the same agent block.",
				Fix:      fmt.Sprintf("Remove the permit at line %d, or change deny! to deny to allow exceptions.", i+1),
			})
			_ = line
		}
	}
	return diags
}

func checkTrustCycles(loc string, tr *ast.Trust) []Diagnostic {
	if tr == nil || len(tr.Delegations) == 0 {
		return nil
	}
	graph := make(map[string][]string)
	for _, d := range tr.Delegations {
		if d.From == "" || d.To == "" {
			continue
		}
		graph[d.From] = append(graph[d.From], d.To)
	}
	visited := make(map[string]bool)
	stack := make(map[string]bool)
	var cycle []string
	var walk func(string) bool
	walk = func(n string) bool {
		if stack[n] {
			cycle = append(cycle, n)
			return true
		}
		if visited[n] {
			return false
		}
		visited[n] = true
		stack[n] = true
		for _, next := range graph[n] {
			if walk(next) {
				cycle = append(cycle, n)
				return true
			}
		}
		delete(stack, n)
		return false
	}
	for start := range graph {
		cycle = nil
		if walk(start) {
			return []Diagnostic{{
				Severity: SeverityError,
				Location: loc,
				What:     "trust delegation cycle detected",
				Why:      fmt.Sprintf("cycle involves %v", cycle),
				Fix:      "Remove or break the delegation cycle in trust{}.",
			}}
		}
	}
	return nil
}
