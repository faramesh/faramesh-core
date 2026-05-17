package fpl

import (
	"fmt"
	"strconv"
)

func (p *parser) parseRateLimitLine() (*RateLimitLine, error) {
	line := p.peek().line
	if err := p.expectIdent("rate_limit"); err != nil {
		return nil, err
	}
	pattern, err := p.stringOrIdent()
	if err != nil {
		return nil, fmt.Errorf("line %d: rate_limit: expected tool pattern", line)
	}
	if p.peek().kind != tkColon {
		return nil, fmt.Errorf("line %d: rate_limit: expected ':' after pattern", line)
	}
	p.next()
	limitTok := p.next()
	limit, err := strconv.ParseInt(limitTok.val, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("line %d: rate_limit: invalid limit %q", line, limitTok.val)
	}
	if err := p.expectIdent("per"); err != nil {
		return nil, fmt.Errorf("line %d: rate_limit: expected 'per <window>'", line)
	}
	window, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	return &RateLimitLine{Pattern: pattern, Limit: limit, Window: window, Line: line}, nil
}

func (p *parser) parseRedactLine() (*RedactLine, error) {
	line := p.peek().line
	if err := p.expectIdent("redact"); err != nil {
		return nil, err
	}
	tool, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if err := p.expectIdent("args"); err != nil {
		return nil, fmt.Errorf("line %d: redact: expected 'args:'", line)
	}
	if p.peek().kind == tkColon {
		p.next()
	}
	paths, err := p.parseStringList()
	if err != nil {
		return nil, fmt.Errorf("line %d: redact: %w", line, err)
	}
	return &RedactLine{Tool: tool, Paths: paths, Line: line}, nil
}

func (p *parser) parseEgressBlock() (*EgressBlock, error) {
	if err := p.expectIdent("egress"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	eg := &EgressBlock{}
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		if p.peek().kind != tkIdent {
			return nil, fmt.Errorf("line %d: expected field name in egress block", p.peek().line)
		}
		key := p.next().val
		p.skipOptionalEquals()
		list, err := p.parseStringList()
		if err != nil {
			return nil, err
		}
		switch key {
		case "allow":
			eg.Allow = list
		case "deny":
			eg.Deny = list
		}
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return eg, nil
}

func (p *parser) parseModelPolicyBlock() (*ModelPolicyBlock, error) {
	if err := p.expectIdent("model_policy"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	mp := &ModelPolicyBlock{}
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		if err := p.expectIdent("allow"); err != nil {
			return nil, err
		}
		p.skipOptionalEquals()
		if p.peek().kind == tkLBracket {
			list, err := p.parseStringList()
			if err != nil {
				return nil, err
			}
			mp.Allow = append(mp.Allow, list...)
		} else {
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			mp.Allow = append(mp.Allow, v)
		}
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return mp, nil
}

func (p *parser) parseSessionBlock() (*SessionBlock, error) {
	if err := p.expectIdent("session"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	sb := &SessionBlock{}
	fields, err := p.parseConfigFieldsInner()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	sb.MaxDuration = configValueString(fields["max_duration"])
	sb.IdleTimeout = configValueString(fields["idle_timeout"])
	return sb, nil
}

func (p *parser) parseSpawnBlock() (*SpawnBlock, error) {
	if err := p.expectIdent("spawn"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	sp := &SpawnBlock{}
	fields, err := p.parseConfigFieldsInner()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	if v, ok := fields["max_concurrent"]; ok && v.Kind == ConfigNumber {
		sp.MaxConcurrent = int(v.Number)
	}
	if v, ok := fields["allowed_types"]; ok {
		list, err := configValueToStringList(v)
		if err == nil {
			sp.AllowedTypes = list
		}
	}
	return sp, nil
}

func (p *parser) parseCompletionGateBlock() (*CompletionGateBlock, error) {
	if err := p.expectIdent("completion_gate"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	cg := &CompletionGateBlock{}
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		if p.peekIdent() == "require" {
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			cg.Requires = append(cg.Requires, v)
			continue
		}
		return nil, fmt.Errorf("line %d: completion_gate: expected 'require <condition>'", p.peek().line)
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return cg, nil
}

func (p *parser) parseEnforcementBlock() (*EnforcementBlock, error) {
	if err := p.expectIdent("enforcement"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	fields, err := p.parseConfigFieldsInner()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return &EnforcementBlock{Fields: fields}, nil
}

func (p *parser) parseAlertBlock() (*AlertBlock, error) {
	if err := p.expectIdent("alert"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	ab := &AlertBlock{}
	fields, err := p.parseConfigFieldsInner()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	ab.On = configValueString(fields["on"])
	ab.Notify = configValueString(fields["notify"])
	return ab, nil
}

func (p *parser) parseStringList() ([]string, error) {
	if _, err := p.expect(tkLBracket); err != nil {
		return nil, err
	}
	var out []string
	for p.peek().kind != tkRBracket && p.peek().kind != tkEOF {
		if p.peek().kind == tkString {
			out = append(out, p.next().val)
		} else if p.peek().kind == tkIdent {
			out = append(out, p.next().val)
		} else {
			return nil, fmt.Errorf("line %d: expected string in list", p.peek().line)
		}
		if p.peek().kind == tkIdent && p.peek().val == "," {
			p.next()
		}
	}
	if _, err := p.expect(tkRBracket); err != nil {
		return nil, err
	}
	return out, nil
}

func configValueString(v ConfigValue) string {
	switch v.Kind {
	case ConfigString, ConfigIdent:
		return v.String
	case ConfigNumber:
		return strconv.FormatFloat(v.Number, 'f', -1, 64)
	case ConfigBool:
		if v.Bool {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func configValueToStringList(v ConfigValue) ([]string, error) {
	if v.Kind != ConfigIdent && v.Kind != ConfigString {
		return nil, fmt.Errorf("expected string list")
	}
	// Lists are parsed directly; single ident is not a list.
	return []string{v.String}, nil
}

func configValueStringOrList(fields map[string]ConfigValue, key string) []string {
	v, ok := fields[key]
	if !ok {
		return nil
	}
	if v.Kind == ConfigString || v.Kind == ConfigIdent {
		return []string{v.String}
	}
	return nil
}
