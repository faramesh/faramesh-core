package governance

import (
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

func providerConfigMap(p *ast.Provider) map[string]string {
	return providerConfigMapWithResolve(p, false)
}

func providerConfigMapResolved(p *ast.Provider) map[string]string {
	return providerConfigMapWithResolve(p, true)
}

func providerConfigMapWithResolve(p *ast.Provider, resolveEnv bool) map[string]string {
	if p == nil {
		return nil
	}
	m := make(map[string]string)
	if p.Type != "" {
		m["type"] = p.Type
	}
	if p.Source != "" {
		m["source"] = p.Source
	}
	for k, v := range p.Config {
		m[k] = valueString(v, resolveEnv)
	}
	return m
}
