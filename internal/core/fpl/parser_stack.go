package fpl

import (
	"fmt"
	"strconv"
	"strings"
)

func (p *parser) parseImportDecl() (ImportDecl, error) {
	line := p.peek().line
	if err := p.expectIdent("import"); err != nil {
		return ImportDecl{}, err
	}
	ref, err := p.stringOrIdent()
	if err != nil {
		return ImportDecl{}, fmt.Errorf("line %d: import: expected registry reference string", line)
	}
	imp := ImportDecl{Ref: ref, Line: line}
	if p.peek().kind == tkIdent && p.peek().val == "as" {
		p.next()
		alias, err := p.stringOrIdent()
		if err != nil {
			return ImportDecl{}, err
		}
		imp.Alias = alias
	}
	return imp, nil
}

func (p *parser) parseRuntimeBlock() (*RuntimeBlock, error) {
	if err := p.expectIdent("runtime"); err != nil {
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
	return &RuntimeBlock{Fields: fields}, nil
}

func (p *parser) parseNamedProviderBlock() (*NamedProviderBlock, error) {
	if err := p.expectIdent("provider"); err != nil {
		return nil, err
	}
	name, err := p.stringOrIdent()
	if err != nil {
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
	return &NamedProviderBlock{Name: name, Fields: fields}, nil
}

func (p *parser) parseNamedIdentityBlock() (*NamedIdentityBlock, error) {
	if err := p.expectIdent("identity"); err != nil {
		return nil, err
	}
	name, err := p.stringOrIdent()
	if err != nil {
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
	return &NamedIdentityBlock{Name: name, Fields: fields}, nil
}

func (p *parser) parseTrustBlock() (*TrustBlock, error) {
	if err := p.expectIdent("trust"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}
	var lines []string
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		line := p.collectLine()
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return &TrustBlock{Raw: lines}, nil
}

func (p *parser) parseConfigFieldsInner() (map[string]ConfigValue, error) {
	out := make(map[string]ConfigValue)
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		keyTok := p.peek()
		if keyTok.kind != tkIdent {
			return nil, fmt.Errorf("line %d: expected field name in block", keyTok.line)
		}
		key := keyTok.val
		p.next()
		p.skipOptionalEquals()
		val, err := p.parseConfigValue()
		if err != nil {
			return nil, fmt.Errorf("line %d: field %q: %w", keyTok.line, key, err)
		}
		out[key] = val
	}
	return out, nil
}

func (p *parser) skipOptionalEquals() {
	if p.peek().kind == tkEq {
		p.next()
	}
}

func (p *parser) parseConfigValue() (ConfigValue, error) {
	line := p.peek().line
	switch p.peek().kind {
	case tkString:
		s := p.next().val
		return ConfigValue{Kind: ConfigString, String: s}, nil
	case tkNumber:
		n, err := strconv.ParseFloat(p.next().val, 64)
		if err != nil {
			return ConfigValue{}, fmt.Errorf("line %d: invalid number", line)
		}
		return ConfigValue{Kind: ConfigNumber, Number: n}, nil
	case tkDollar:
		p.next()
		if p.peek().kind != tkNumber {
			return ConfigValue{}, fmt.Errorf("line %d: expected amount after $", line)
		}
		n, err := strconv.ParseFloat(p.next().val, 64)
		if err != nil {
			return ConfigValue{}, err
		}
		return ConfigValue{Kind: ConfigNumber, Number: n}, nil
	case tkIdent:
		id := p.next().val
		if id == "true" {
			return ConfigValue{Kind: ConfigBool, Bool: true}, nil
		}
		if id == "false" {
			return ConfigValue{Kind: ConfigBool, Bool: false}, nil
		}
		if id == "env" {
			return p.parseEnvCall()
		}
		return ConfigValue{Kind: ConfigIdent, String: id}, nil
	default:
		return ConfigValue{}, fmt.Errorf("line %d: unexpected value token %q", line, p.peek().val)
	}
}

func (p *parser) parseEnvCall() (ConfigValue, error) {
	line := p.peek().line
	if _, err := p.expect(tkLParen); err != nil {
		return ConfigValue{}, fmt.Errorf("line %d: env: expected '('", line)
	}
	if p.peek().kind != tkString {
		return ConfigValue{}, fmt.Errorf("line %d: env: expected variable name in quotes", line)
	}
	name := p.next().val
	if _, err := p.expect(tkRParen); err != nil {
		return ConfigValue{}, fmt.Errorf("line %d: env: expected ')'", line)
	}
	if strings.TrimSpace(name) == "" {
		return ConfigValue{}, fmt.Errorf("line %d: env: variable name must not be empty", line)
	}
	return ConfigValue{Kind: ConfigEnv, EnvVar: name}, nil
}
