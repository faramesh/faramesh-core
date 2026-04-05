package fpl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Rule is a single flat rule line (backward-compatible with v0 FPL).
type Rule struct {
	Effect    string
	Tool      string
	Condition string
	Notify    string
	Reason    string
}

// ── Full Structured FPL AST ────────────────────────────────────────────────

// Document is the top-level AST node for a structured FPL file.
type Document struct {
	Agents  []*AgentBlock
	Systems []*SystemBlock
	// Flat rules at top level (backward-compatible with v0 FPL).
	FlatRules []*Rule
	Topo      []TopoStatement
}

type AgentBlock struct {
	ID          string
	Default     string // "deny" | "permit"
	Model       string
	Framework   string
	Version     string
	Budgets     []*BudgetBlock
	Phases      []*PhaseBlock
	Rules       []*Rule
	Delegates   []*DelegateBlock
	Ambients    []*AmbientBlock
	Selectors   []*SelectorBlock
	Credentials []*CredentialBlock
	Vars        map[string]string
}

type SystemBlock struct {
	ID                  string
	Version             string
	OnPolicyLoadFailure string
	KillSwitchDefault   string
	MaxOutputBytes      int
}

type BudgetBlock struct {
	ID       string // "session" | "daily" | custom
	Max      float64
	Daily    float64
	MaxCalls int64
	OnExceed string
}

type PhaseBlock struct {
	ID       string
	Tools    []string
	Rules    []*Rule
	Duration string
	Next     string
}

type DelegateBlock struct {
	TargetAgent string
	Scope       string
	TTL         string
	Ceiling     string
}

type AmbientBlock struct {
	Limits   map[string]string
	OnExceed string
}

type SelectorBlock struct {
	ID            string
	Source        string
	Cache         string
	OnUnavailable string
	OnTimeout     string
}

type CredentialBlock struct {
	ID       string
	Scope    []string
	MaxScope string
	Backend  string
	Path     string
	TTL      string
}

// ── Recursive Descent Parser ───────────────────────────────────────────────

type parser struct {
	src    string
	tokens []token
	pos    int
}

type tokenKind int

const (
	tkIdent tokenKind = iota
	tkString
	tkNumber
	tkLBrace
	tkRBrace
	tkColon
	tkBang
	tkDollar
	tkEOF
)

type token struct {
	kind tokenKind
	val  string
	line int
}

func tokenize(src string) ([]token, error) {
	var tokens []token
	line := 1
	i := 0
	for i < len(src) {
		ch := src[i]
		switch {
		case ch == '\n':
			line++
			i++
		case ch == '\r':
			i++
		case ch == ' ' || ch == '\t':
			i++
		case ch == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case ch == '{':
			tokens = append(tokens, token{tkLBrace, "{", line})
			i++
		case ch == '}':
			tokens = append(tokens, token{tkRBrace, "}", line})
			i++
		case ch == ':':
			tokens = append(tokens, token{tkColon, ":", line})
			i++
		case ch == '!' && (i+1 >= len(src) || src[i+1] == ' ' || src[i+1] == '\t' || src[i+1] == '\n' || src[i+1] == '\r'):
			tokens = append(tokens, token{tkBang, "!", line})
			i++
		case ch == '!':
			j := i
			for j < len(src) && isIdentCont(src[j]) {
				j++
			}
			tokens = append(tokens, token{tkIdent, src[i:j], line})
			i = j
		case ch == '$':
			tokens = append(tokens, token{tkDollar, "$", line})
			i++
		case ch == '"' || ch == '\'':
			quote := ch
			j := i + 1
			for j < len(src) && src[j] != quote {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("line %d: unterminated string", line)
			}
			tokens = append(tokens, token{tkString, src[i+1 : j], line})
			i = j + 1
		case isDigit(ch) || (ch == '-' && i+1 < len(src) && isDigit(src[i+1])):
			j := i
			if ch == '-' {
				j++
			}
			for j < len(src) && (isDigit(src[j]) || src[j] == '.') {
				j++
			}
			tokens = append(tokens, token{tkNumber, src[i:j], line})
			i = j
		case isIdentStart(ch):
			j := i
			for j < len(src) && isIdentCont(src[j]) {
				j++
			}
			tokens = append(tokens, token{tkIdent, src[i:j], line})
			i = j
		default:
			return nil, fmt.Errorf("line %d: unexpected character %q", line, string(ch))
		}
	}
	tokens = append(tokens, token{tkEOF, "", line})
	return tokens, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
		c == '>' || c == '<' || c == '=' || c == '(' || c == ')' ||
		c == '[' || c == ']' || c == ',' || c == '/' || c == '*' || c == '+' || c == '&' || c == '|'
}
func isIdentCont(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '-' || c == '.' || c == '!' || c == '@' || c == '%' || c == '^'
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tkEOF, "", 0}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if t.kind != tkEOF {
		p.pos++
	}
	return t
}

func (p *parser) expect(kind tokenKind) (token, error) {
	t := p.next()
	if t.kind != kind {
		return t, fmt.Errorf("line %d: expected %v, got %q", t.line, kind, t.val)
	}
	return t, nil
}

func (p *parser) expectIdent(val string) error {
	t := p.next()
	if t.kind != tkIdent || t.val != val {
		return fmt.Errorf("line %d: expected %q, got %q", t.line, val, t.val)
	}
	return nil
}

func (p *parser) peekIdent() string {
	t := p.peek()
	if t.kind == tkIdent {
		return t.val
	}
	return ""
}

func (p *parser) stringOrIdent() (string, error) {
	t := p.peek()
	switch t.kind {
	case tkString:
		p.next()
		return t.val, nil
	case tkIdent:
		p.next()
		return t.val, nil
	case tkNumber:
		p.next()
		// Absorb trailing unit suffix (e.g., "24h", "10mb", "30s").
		if p.peek().kind == tkIdent && isUnitSuffix(p.peek().val) {
			unit := p.next()
			return t.val + unit.val, nil
		}
		return t.val, nil
	default:
		return "", fmt.Errorf("line %d: expected string or identifier, got %q", t.line, t.val)
	}
}

// ParseDocument parses a full structured FPL document.
func ParseDocument(src string) (*Document, error) {
	tokens, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, tokens: tokens}
	return p.parseDocument()
}

func (p *parser) parseDocument() (*Document, error) {
	doc := &Document{}

	for p.peek().kind != tkEOF {
		t := p.peek()
		if t.kind != tkIdent {
			return nil, fmt.Errorf("line %d: unexpected token %q", t.line, t.val)
		}

		switch t.val {
		case "agent":
			ab, err := p.parseAgentBlock()
			if err != nil {
				return nil, err
			}
			doc.Agents = append(doc.Agents, ab)

		case "system":
			sb, err := p.parseSystemBlock()
			if err != nil {
				return nil, err
			}
			doc.Systems = append(doc.Systems, sb)

		case "manifest":
			topo, remaining, err := scanManifestLines(p.collectLine())
			if err != nil {
				return nil, err
			}
			doc.Topo = append(doc.Topo, topo...)
			_ = remaining

		case "permit", "allow", "approve", "deny", "block", "reject", "defer", "deny!":
			rule, err := p.parseFlatRule()
			if err != nil {
				return nil, err
			}
			doc.FlatRules = append(doc.FlatRules, rule)

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q", t.line, t.val)
		}
	}
	return doc, nil
}

func (p *parser) collectLine() string {
	start := p.pos
	line := p.peek().line
	for p.peek().kind != tkEOF && p.peek().line == line {
		p.next()
	}
	var parts []string
	for i := start; i < p.pos; i++ {
		parts = append(parts, p.tokens[i].val)
	}
	return strings.Join(parts, " ")
}

func (p *parser) parseFlatRule() (*Rule, error) {
	effectTok := p.next()
	effect := effectTok.val

	// Handle deny! — either as a single ident "deny!" or as "deny" followed by tkBang.
	if effect == "deny" && p.peek().kind == tkBang {
		p.next()
		effect = "deny!"
	}
	// deny! may have been tokenized as a single ident.
	// (already handled: effect == "deny!")

	tool, err := p.stringOrIdent()
	if err != nil {
		return nil, fmt.Errorf("line %d: rule tool: %w", effectTok.line, err)
	}

	rule := &Rule{Effect: effect, Tool: tool}

	// Consume optional clauses on the same logical grouping
	for p.peek().kind != tkEOF {
		ident := p.peekIdent()
		switch ident {
		case "when":
			p.next()
			cond, err := p.consumeUntilKeyword()
			if err != nil {
				return nil, err
			}
			rule.Condition = cond
		case "notify":
			p.next()
			if p.peek().kind == tkColon {
				p.next()
			}
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			rule.Notify = v
		case "reason":
			p.next()
			if p.peek().kind == tkColon {
				p.next()
			}
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			rule.Reason = v
		default:
			return rule, nil
		}
	}
	return rule, nil
}

func (p *parser) consumeUntilKeyword() (string, error) {
	startLine := p.peek().line
	var parts []string
	for {
		t := p.peek()
		if t.kind == tkEOF || t.kind == tkLBrace || t.kind == tkRBrace {
			break
		}
		if t.kind == tkIdent && (t.val == "notify" || t.val == "reason") {
			break
		}
		if t.kind == tkIdent && isEffectKeyword(t.val) && t.line != startLine {
			break
		}
		if t.kind == tkIdent && isTopLevelKeyword(t.val) {
			break
		}
		p.next()
		val := t.val
		if t.kind == tkString {
			val = `"` + val + `"`
		} else if t.kind == tkColon {
			val = ":"
		} else if t.kind == tkDollar {
			val = "$"
		} else if t.kind == tkBang {
			val = "!"
		}
		parts = append(parts, val)
	}
	return strings.Join(parts, " "), nil
}

func isTopLevelKeyword(s string) bool {
	switch s {
	case "agent", "system", "permit", "allow", "approve", "deny", "deny!", "block", "reject", "defer", "manifest":
		return true
	}
	return false
}

func isCredentialKeyword(s string) bool {
	switch s {
	case "scope", "max_scope", "backend", "path", "ttl":
		return true
	}
	return false
}

func isUnitSuffix(s string) bool {
	switch strings.ToLower(s) {
	case "s", "ms", "m", "h", "d", "w",
		"b", "kb", "mb", "gb", "tb",
		"usd", "eur", "gbp":
		return true
	}
	return false
}

func isEffectKeyword(s string) bool {
	switch s {
	case "permit", "allow", "approve", "deny", "deny!", "block", "reject", "defer":
		return true
	}
	return false
}

func (p *parser) parseAgentBlock() (*AgentBlock, error) {
	if err := p.expectIdent("agent"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	ab := &AgentBlock{ID: id, Vars: make(map[string]string)}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "default":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.Default = v

		case "model":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.Model = v

		case "framework":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.Framework = v

		case "version":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.Version = v

		case "var":
			p.next()
			name, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			val, err := p.parseVarValue()
			if err != nil {
				return nil, err
			}
			ab.Vars[name] = val

		case "budget":
			bb, err := p.parseBudgetBlock()
			if err != nil {
				return nil, err
			}
			ab.Budgets = append(ab.Budgets, bb)

		case "phase":
			pb, err := p.parsePhaseBlock()
			if err != nil {
				return nil, err
			}
			ab.Phases = append(ab.Phases, pb)

		case "rules":
			rules, err := p.parseRulesBlock()
			if err != nil {
				return nil, err
			}
			ab.Rules = append(ab.Rules, rules...)

		case "delegate":
			db, err := p.parseDelegateBlock()
			if err != nil {
				return nil, err
			}
			ab.Delegates = append(ab.Delegates, db)

		case "ambient":
			amb, err := p.parseAmbientBlock()
			if err != nil {
				return nil, err
			}
			ab.Ambients = append(ab.Ambients, amb)

		case "selector":
			sel, err := p.parseSelectorBlock()
			if err != nil {
				return nil, err
			}
			ab.Selectors = append(ab.Selectors, sel)

		case "credential":
			cred, err := p.parseCredentialBlock()
			if err != nil {
				return nil, err
			}
			ab.Credentials = append(ab.Credentials, cred)

		case "permit", "allow", "approve", "deny", "block", "reject", "defer", "deny!":
			rule, err := p.parseFlatRule()
			if err != nil {
				return nil, err
			}
			ab.Rules = append(ab.Rules, rule)

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in agent block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("agent %s: %w", id, err)
	}
	return ab, nil
}

func (p *parser) parseSystemBlock() (*SystemBlock, error) {
	if err := p.expectIdent("system"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	sb := &SystemBlock{ID: id}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "version":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.Version = v

		case "on_policy_load_failure":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.OnPolicyLoadFailure = v

		case "kill_switch_default":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.KillSwitchDefault = v

		case "max_output_bytes":
			p.next()
			t := p.next()
			n, err := strconv.Atoi(t.val)
			if err != nil {
				return nil, fmt.Errorf("line %d: max_output_bytes: %w", t.line, err)
			}
			sb.MaxOutputBytes = n

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in system block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("system %s: %w", id, err)
	}
	return sb, nil
}

func (p *parser) parseBudgetBlock() (*BudgetBlock, error) {
	if err := p.expectIdent("budget"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	bb := &BudgetBlock{ID: id}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "max":
			p.next()
			v, err := p.parseCurrency()
			if err != nil {
				return nil, err
			}
			bb.Max = v

		case "daily":
			p.next()
			v, err := p.parseCurrency()
			if err != nil {
				return nil, err
			}
			bb.Daily = v

		case "max_calls":
			p.next()
			t := p.next()
			n, err := strconv.ParseInt(t.val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: max_calls: %w", t.line, err)
			}
			bb.MaxCalls = n

		case "on_exceed":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			bb.OnExceed = v

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in budget block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("budget %s: %w", id, err)
	}
	return bb, nil
}

func (p *parser) parseCurrency() (float64, error) {
	if p.peek().kind == tkDollar {
		p.next()
	}
	t := p.next()
	v, err := strconv.ParseFloat(t.val, 64)
	if err != nil {
		return 0, fmt.Errorf("line %d: expected number, got %q", t.line, t.val)
	}
	return v, nil
}

func (p *parser) parsePhaseBlock() (*PhaseBlock, error) {
	if err := p.expectIdent("phase"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	pb := &PhaseBlock{ID: id}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "permit", "allow", "approve", "deny", "deny!", "block", "reject", "defer":
			rule, err := p.parseFlatRule()
			if err != nil {
				return nil, err
			}
			pb.Rules = append(pb.Rules, rule)
			pb.Tools = append(pb.Tools, rule.Tool)

		case "duration":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			pb.Duration = v

		case "next":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			pb.Next = v

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in phase block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("phase %s: %w", id, err)
	}
	return pb, nil
}

func (p *parser) parseRulesBlock() ([]*Rule, error) {
	if err := p.expectIdent("rules"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	var rules []*Rule
	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		rule, err := p.parseFlatRule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return rules, nil
}

func (p *parser) parseDelegateBlock() (*DelegateBlock, error) {
	if err := p.expectIdent("delegate"); err != nil {
		return nil, err
	}
	target, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	db := &DelegateBlock{TargetAgent: target}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "scope":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			db.Scope = v

		case "ttl":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			db.TTL = v

		case "ceiling":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			db.Ceiling = v

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in delegate block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("delegate %s: %w", target, err)
	}
	return db, nil
}

func (p *parser) parseAmbientBlock() (*AmbientBlock, error) {
	if err := p.expectIdent("ambient"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	ab := &AmbientBlock{Limits: make(map[string]string)}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		if kw == "on_exceed" {
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.OnExceed = v
		} else if kw != "" {
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			ab.Limits[kw] = v
		} else {
			return nil, fmt.Errorf("line %d: unexpected token in ambient block", p.peek().line)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, err
	}
	return ab, nil
}

func (p *parser) parseSelectorBlock() (*SelectorBlock, error) {
	if err := p.expectIdent("selector"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	sb := &SelectorBlock{ID: id}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "source":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.Source = v

		case "cache":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.Cache = v

		case "on_unavailable":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.OnUnavailable = v

		case "on_timeout":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			sb.OnTimeout = v

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in selector block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("selector %s: %w", id, err)
	}
	return sb, nil
}

func (p *parser) parseCredentialBlock() (*CredentialBlock, error) {
	if err := p.expectIdent("credential"); err != nil {
		return nil, err
	}
	id, err := p.stringOrIdent()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkLBrace); err != nil {
		return nil, err
	}

	cb := &CredentialBlock{ID: id}

	for p.peek().kind != tkRBrace && p.peek().kind != tkEOF {
		kw := p.peekIdent()
		switch kw {
		case "scope":
			p.next()
			for p.peek().kind == tkIdent || p.peek().kind == tkString {
				if p.peek().kind == tkIdent && isCredentialKeyword(p.peek().val) {
					break
				}
				v, _ := p.stringOrIdent()
				cb.Scope = append(cb.Scope, v)
			}

		case "max_scope":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			cb.MaxScope = v

		case "backend":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			cb.Backend = v

		case "path":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			cb.Path = v

		case "ttl":
			p.next()
			v, err := p.stringOrIdent()
			if err != nil {
				return nil, err
			}
			cb.TTL = v

		default:
			return nil, fmt.Errorf("line %d: unexpected keyword %q in credential block", p.peek().line, kw)
		}
	}

	if _, err := p.expect(tkRBrace); err != nil {
		return nil, fmt.Errorf("credential %s: %w", id, err)
	}
	return cb, nil
}

func (p *parser) parseVarValue() (string, error) {
	t := p.peek()
	switch t.kind {
	case tkString:
		p.next()
		return t.val, nil
	case tkNumber:
		p.next()
		return t.val, nil
	case tkDollar:
		p.next()
		n := p.next()
		return "$" + n.val, nil
	case tkIdent:
		p.next()
		return t.val, nil
	default:
		return "", fmt.Errorf("line %d: expected value, got %q", t.line, t.val)
	}
}

// ── Backward-compatible v0 API ─────────────────────────────────────────────

// ParseRules parses flat FPL rule lines (v0 format). Manifest lines are separated out.
func ParseRules(src string) ([]*Rule, error) {
	p, err := ParseProgram(src)
	if err != nil {
		return nil, err
	}
	return p.Rules, nil
}

// ParseProgram parses FPL source into rules and topology manifest statements (v0 API).
func ParseProgram(src string) (*ParsedFile, error) {
	topo, rulesSrc, err := scanManifestLines(src)
	if err != nil {
		return nil, err
	}

	// Try structured parse first; if it fails or produces only flat rules, use that.
	doc, docErr := ParseDocument(src)
	if docErr == nil && len(doc.Agents) > 0 {
		pf := &ParsedFile{Topo: doc.Topo}
		for _, ag := range doc.Agents {
			pf.Rules = append(pf.Rules, ag.Rules...)
			for _, ph := range ag.Phases {
				pf.Rules = append(pf.Rules, ph.Rules...)
			}
		}
		pf.Rules = append(pf.Rules, doc.FlatRules...)
		return pf, nil
	}

	// Fall back to v0 flat parsing via manual scan.
	if strings.TrimSpace(rulesSrc) == "" {
		return &ParsedFile{Topo: topo}, nil
	}
	rules, err := parseFlatRulesV0(rulesSrc)
	if err != nil {
		return nil, fmt.Errorf("parse fpl: %w", err)
	}
	return &ParsedFile{Rules: rules, Topo: topo}, nil
}

// parseFlatRulesV0 is the v0 flat rule parser using the hand-written tokenizer.
func parseFlatRulesV0(src string) ([]*Rule, error) {
	tokens, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, tokens: tokens}
	var rules []*Rule
	for p.peek().kind != tkEOF {
		rule, err := p.parseFlatRule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ParsedFile is the result of parsing a single FPL document (rules + optional topology).
type ParsedFile struct {
	Rules []*Rule
	Topo  []TopoStatement
}

func trimQuotes(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += " " + parts[i]
	}
	return out
}

// ── Decompiler (YAML → FPL) ────────────────────────────────────────────────

// DecompileToFPL converts a policy.Doc-compatible structure back to FPL source text.
// This is used by `faramesh policy fpl decompile`.
func DecompileToFPL(agentID, defaultEffect string, vars map[string]string,
	phases map[string][]string, rules []DecompileRule, budget *DecompileBudget,
	delegates []DecompileDelegate, ambient *DecompileAmbient, selectors []DecompileSelector) string {

	var b strings.Builder

	b.WriteString("agent ")
	b.WriteString(agentID)
	b.WriteString(" {\n")

	if defaultEffect != "" {
		b.WriteString("  default ")
		b.WriteString(defaultEffect)
		b.WriteString("\n")
	}

	varKeys := make([]string, 0, len(vars))
	for k := range vars {
		varKeys = append(varKeys, k)
	}
	sort.Strings(varKeys)
	for _, k := range varKeys {
		v := vars[k]
		b.WriteString("  var ")
		b.WriteString(k)
		b.WriteString(" ")
		if needsQuotes(v) {
			b.WriteString(`"` + v + `"`)
		} else {
			b.WriteString(v)
		}
		b.WriteString("\n")
	}

	if budget != nil {
		b.WriteString("\n  budget session {\n")
		if budget.SessionUSD > 0 {
			b.WriteString(fmt.Sprintf("    max $%.0f\n", budget.SessionUSD))
		}
		if budget.DailyUSD > 0 {
			b.WriteString(fmt.Sprintf("    daily $%.0f\n", budget.DailyUSD))
		}
		if budget.MaxCalls > 0 {
			b.WriteString(fmt.Sprintf("    max_calls %d\n", budget.MaxCalls))
		}
		if budget.OnExceed != "" {
			b.WriteString("    on_exceed ")
			b.WriteString(budget.OnExceed)
			b.WriteString("\n")
		}
		b.WriteString("  }\n")
	}

	phaseNames := make([]string, 0, len(phases))
	for name := range phases {
		phaseNames = append(phaseNames, name)
	}
	sort.Strings(phaseNames)
	for _, name := range phaseNames {
		tools := phases[name]
		b.WriteString("\n  phase ")
		b.WriteString(name)
		b.WriteString(" {\n")
		for _, t := range tools {
			b.WriteString("    permit ")
			b.WriteString(t)
			b.WriteString("\n")
		}
		b.WriteString("  }\n")
	}

	if len(delegates) > 0 {
		for _, d := range delegates {
			target := strings.TrimSpace(d.TargetAgent)
			if target == "" {
				continue
			}
			b.WriteString("\n  delegate ")
			if needsQuotes(target) {
				b.WriteString(`"` + target + `"`)
			} else {
				b.WriteString(target)
			}
			b.WriteString(" {\n")
			if scope := strings.TrimSpace(d.Scope); scope != "" {
				b.WriteString("    scope ")
				if needsQuotes(scope) {
					b.WriteString(`"` + scope + `"`)
				} else {
					b.WriteString(scope)
				}
				b.WriteString("\n")
			}
			if ttl := strings.TrimSpace(d.TTL); ttl != "" {
				b.WriteString("    ttl ")
				if needsQuotes(ttl) {
					b.WriteString(`"` + ttl + `"`)
				} else {
					b.WriteString(ttl)
				}
				b.WriteString("\n")
			}
			if ceiling := strings.TrimSpace(d.Ceiling); ceiling != "" {
				b.WriteString("    ceiling ")
				if needsQuotes(ceiling) {
					b.WriteString(`"` + ceiling + `"`)
				} else {
					b.WriteString(ceiling)
				}
				b.WriteString("\n")
			}
			b.WriteString("  }\n")
		}
	}

	if ambient != nil && (len(ambient.Limits) > 0 || strings.TrimSpace(ambient.OnExceed) != "") {
		b.WriteString("\n  ambient {\n")
		keys := make([]string, 0, len(ambient.Limits))
		for k := range ambient.Limits {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			val := strings.TrimSpace(ambient.Limits[key])
			if val == "" {
				continue
			}
			b.WriteString("    ")
			b.WriteString(key)
			b.WriteString(" ")
			if needsQuotes(val) {
				b.WriteString(`"` + val + `"`)
			} else {
				b.WriteString(val)
			}
			b.WriteString("\n")
		}
		if onExceed := strings.TrimSpace(ambient.OnExceed); onExceed != "" {
			b.WriteString("    on_exceed ")
			if needsQuotes(onExceed) {
				b.WriteString(`"` + onExceed + `"`)
			} else {
				b.WriteString(onExceed)
			}
			b.WriteString("\n")
		}
		b.WriteString("  }\n")
	}

	if len(selectors) > 0 {
		sorted := append([]DecompileSelector(nil), selectors...)
		sort.Slice(sorted, func(i, j int) bool {
			return strings.TrimSpace(sorted[i].ID) < strings.TrimSpace(sorted[j].ID)
		})
		for _, s := range sorted {
			id := strings.TrimSpace(s.ID)
			if id == "" {
				continue
			}
			b.WriteString("\n  selector ")
			if needsQuotes(id) {
				b.WriteString(`"` + id + `"`)
			} else {
				b.WriteString(id)
			}
			b.WriteString(" {\n")
			if source := strings.TrimSpace(s.Source); source != "" {
				b.WriteString("    source ")
				if needsQuotes(source) {
					b.WriteString(`"` + source + `"`)
				} else {
					b.WriteString(source)
				}
				b.WriteString("\n")
			}
			if cache := strings.TrimSpace(s.Cache); cache != "" {
				b.WriteString("    cache ")
				if needsQuotes(cache) {
					b.WriteString(`"` + cache + `"`)
				} else {
					b.WriteString(cache)
				}
				b.WriteString("\n")
			}
			if onUnavailable := strings.TrimSpace(s.OnUnavailable); onUnavailable != "" {
				b.WriteString("    on_unavailable ")
				if needsQuotes(onUnavailable) {
					b.WriteString(`"` + onUnavailable + `"`)
				} else {
					b.WriteString(onUnavailable)
				}
				b.WriteString("\n")
			}
			if onTimeout := strings.TrimSpace(s.OnTimeout); onTimeout != "" {
				b.WriteString("    on_timeout ")
				if needsQuotes(onTimeout) {
					b.WriteString(`"` + onTimeout + `"`)
				} else {
					b.WriteString(onTimeout)
				}
				b.WriteString("\n")
			}
			b.WriteString("  }\n")
		}
	}

	if len(rules) > 0 {
		b.WriteString("\n  rules {\n")
		for _, r := range rules {
			b.WriteString("    ")
			b.WriteString(r.Effect)
			if r.StrictDeny {
				b.WriteString("!")
			}
			b.WriteString(" ")
			b.WriteString(r.Tool)
			if r.When != "" && r.When != "true" {
				b.WriteString(" when ")
				b.WriteString(r.When)
			}
			if r.Notify != "" {
				b.WriteString(" notify: ")
				b.WriteString(`"` + r.Notify + `"`)
			}
			if r.Reason != "" {
				b.WriteString(" reason: ")
				b.WriteString(`"` + r.Reason + `"`)
			}
			b.WriteString("\n")
		}
		b.WriteString("  }\n")
	}

	b.WriteString("}\n")
	return b.String()
}

type DecompileRule struct {
	Effect     string
	Tool       string
	When       string
	Notify     string
	Reason     string
	StrictDeny bool
}

type DecompileBudget struct {
	SessionUSD float64
	DailyUSD   float64
	MaxCalls   int64
	OnExceed   string
}

type DecompileDelegate struct {
	TargetAgent string
	Scope       string
	TTL         string
	Ceiling     string
}

type DecompileAmbient struct {
	Limits   map[string]string
	OnExceed string
}

type DecompileSelector struct {
	ID            string
	Source        string
	Cache         string
	OnUnavailable string
	OnTimeout     string
}

func needsQuotes(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || r == '"' {
			return true
		}
	}
	return !isBareFPLLiteral(s)
}

func isBareFPLLiteral(s string) bool {
	b := []byte(s)
	if len(b) == 0 {
		return false
	}

	if isIdentStart(b[0]) {
		for i := 1; i < len(b); i++ {
			if !isIdentCont(b[i]) {
				return false
			}
		}
		return true
	}

	if isDigit(b[0]) || (b[0] == '-' && len(b) > 1 && isDigit(b[1])) {
		i := 0
		if b[0] == '-' {
			i++
		}
		hasDot := false
		for i < len(b) && (isDigit(b[i]) || b[i] == '.') {
			if b[i] == '.' {
				if hasDot {
					return false
				}
				hasDot = true
			}
			i++
		}
		if i == len(b) {
			return true
		}
		return isUnitSuffix(string(b[i:]))
	}

	return false
}
