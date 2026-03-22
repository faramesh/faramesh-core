package fpl

import (
	"fmt"
	"strings"
)

// ParsedFile is the result of parsing a single FPL document (rules + optional topology).
type ParsedFile struct {
	Rules []*Rule
	Topo  []TopoStatement
}

// ParseProgram parses FPL source into rules and topology manifest statements.
func ParseProgram(src string) (*ParsedFile, error) {
	topo, rulesSrc, err := scanManifestLines(src)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rulesSrc) == "" {
		return &ParsedFile{Topo: topo}, nil
	}
	ast, err := fplParser.ParseString("", rulesSrc)
	if err != nil {
		return nil, fmt.Errorf("parse fpl: %w", err)
	}
	out := &ParsedFile{Topo: topo}
	for _, parsed := range ast.Rules {
		r := &Rule{
			Effect: parsed.Effect,
			Tool:   trimQuotes(parsed.Tool),
		}
		if parsed.When != nil {
			r.Condition = joinParts(parsed.When.Parts)
		}
		if parsed.Notify != nil {
			r.Notify = trimQuotes(parsed.Notify.Value)
		}
		if parsed.Reason != nil {
			r.Reason = trimQuotes(parsed.Reason.Value)
		}
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}
