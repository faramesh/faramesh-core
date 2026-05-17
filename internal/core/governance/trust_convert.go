package governance

import (
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

func trustFromFPL(tb *fpl.TrustBlock) *ast.Trust {
	if tb == nil || len(tb.Raw) == 0 {
		return nil
	}
	tr := &ast.Trust{}
	for _, line := range tb.Raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if d := parseTrustDelegation(line); d != nil {
			tr.Delegations = append(tr.Delegations, *d)
			continue
		}
		if in := parseTrustInbound(line); in != nil {
			tr.Inbound = append(tr.Inbound, *in)
		}
	}
	if len(tr.Delegations) == 0 && len(tr.Inbound) == 0 {
		return nil
	}
	return tr
}

func parseTrustDelegation(line string) *ast.TrustDelegation {
	// delegation from "a" to "b" ceiling inherited scope [s1, s2]
	if !strings.HasPrefix(line, "delegation ") {
		return nil
	}
	fields := splitQuotedFields(line)
	if len(fields) < 4 {
		return nil
	}
	return &ast.TrustDelegation{
		From:    fields[1],
		To:      fields[3],
		Ceiling: findKV(line, "ceiling"),
		Scope:   findBracketList(line, "scope"),
	}
}

func parseTrustInbound(line string) *ast.TrustInbound {
	if !strings.HasPrefix(line, "inbound ") {
		return nil
	}
	return &ast.TrustInbound{
		AgentID:   findQuoted(line),
		Auth:      findKV(line, "auth"),
		Endpoints: findBracketList(line, "endpoints"),
		Scope:     findBracketList(line, "scope"),
	}
}

func splitQuotedFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, strings.Trim(cur.String(), `"`))
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.Trim(cur.String(), `"`))
	}
	return out
}

func findQuoted(line string) string {
	i := strings.Index(line, `"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(line[i+1:], `"`)
	if j < 0 {
		return ""
	}
	return line[i+1 : i+1+j]
}

func findKV(line, key string) string {
	idx := strings.Index(line, key+" ")
	if idx < 0 {
		idx = strings.Index(line, key+"=")
	}
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len(key):])
	rest = strings.TrimPrefix(rest, "=")
	if strings.HasPrefix(rest, `"`) {
		return findQuoted(rest)
	}
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return ""
	}
	return strings.Trim(parts[0], `"`)
}

func findBracketList(line, key string) []string {
	idx := strings.Index(line, key+" [")
	if idx < 0 {
		return nil
	}
	rest := line[idx+len(key):]
	start := strings.Index(rest, "[")
	end := strings.Index(rest, "]")
	if start < 0 || end <= start {
		return nil
	}
	inner := rest[start+1 : end]
	var items []string
	for _, p := range strings.Split(inner, ",") {
		p = strings.Trim(strings.TrimSpace(p), `"`)
		if p != "" {
			items = append(items, p)
		}
	}
	return items
}
