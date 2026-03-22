package fpl

import (
	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

type Rule struct {
	Effect    string
	Tool      string
	Condition string
	Notify    string
	Reason    string
}

var fplLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "comment", Pattern: `#[^\n]*`},
	{Name: "whitespace", Pattern: `\s+`},
	{Name: "String", Pattern: `"([^"\\]|\\.)*"`},
	{Name: "Effect", Pattern: `permit|allow|approve|deny!|deny|block|reject|defer`},
	{Name: "When", Pattern: `when`},
	{Name: "Notify", Pattern: `notify:`},
	{Name: "Reason", Pattern: `reason:`},
	{Name: "Ident", Pattern: `[^\s#"]+`},
})

// Rules-only document (topology uses manifest_line.go scanner).
type fplRulesFile struct {
	Rules []*fplRuleLine `@@*`
}

type fplRuleLine struct {
	Effect string            `@Effect`
	Tool   string            `@(String | Ident)`
	When   *fplWhenClause    `@@?`
	Notify *fplNotifyClause  `@@?`
	Reason *fplReasonClause  `@@?`
}

type fplWhenClause struct {
	Keyword string   `@When`
	Parts   []string `@(String | Ident)+`
}

type fplNotifyClause struct {
	Keyword string `@Notify`
	Value   string `@(String | Ident)`
}

type fplReasonClause struct {
	Keyword string `@Reason`
	Value   string `@(String | Ident)`
}

var fplParser = participle.MustBuild[fplRulesFile](
	participle.Lexer(fplLexer),
)

// ParseRules parses FPL into tool governance rules (manifest lines are ignored).
func ParseRules(src string) ([]*Rule, error) {
	p, err := ParseProgram(src)
	if err != nil {
		return nil, err
	}
	return p.Rules, nil
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

func trimQuotes(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}
