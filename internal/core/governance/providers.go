package governance

import (
	"context"
	"fmt"

	"github.com/faramesh/faramesh-core/internal/provider"
)

// ProviderCompiled is a serialized provider block in governance.compiled.json.
type ProviderCompiled struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Source string            `json:"source,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

// ProviderSpecs returns provider.Spec values from a compiled stack.
func (c *Compiled) ProviderSpecs() []provider.Spec {
	if c == nil || len(c.Providers) == 0 {
		return nil
	}
	out := make([]provider.Spec, 0, len(c.Providers))
	for _, p := range c.Providers {
		out = append(out, provider.Spec{
			Name:   p.Name,
			Type:   p.Type,
			Source: p.Source,
			Config: p.Config,
		})
	}
	return out
}

// CheckProviders runs Init(dry_run=true) for each provider and returns diagnostics.
func CheckProviders(ctx context.Context, stackDir string, specs []provider.Spec, sourcePath string) []Diagnostic {
	var diags []Diagnostic
	loc := sourcePath
	if loc == "" {
		loc = "governance.fms"
	}
	reg := provider.NewRegistry(stackDir)
	for _, spec := range specs {
		if err := reg.Register(spec); err != nil {
			diags = append(diags, Diagnostic{
				Severity: SeverityError,
				Location: fmt.Sprintf("%s — provider %q", loc, spec.Name),
				What:     err.Error(),
				Why:      "Provider blocks must have unique names.",
				Fix:      "Rename or remove the duplicate provider block.",
			})
		}
	}
	if HasErrors(diags) {
		return diags
	}
	if len(specs) == 0 {
		return diags
	}
	if err := reg.InitAll(ctx, true); err != nil {
		diags = append(diags, Diagnostic{
			Severity: SeverityError,
			Location: loc,
			What:     err.Error(),
			Why:      "Provider Init dry-run validation failed.",
			Fix:      "Fix the provider block configuration and referenced environment variables.",
		})
	}
	_ = reg.Close(ctx)
	return diags
}
