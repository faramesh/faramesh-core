package policy

import (
	"strings"
	"testing"
)

func TestCompileExprAcceptsBoundaryLimits(t *testing.T) {
	t.Run("max chars accepted", func(t *testing.T) {
		exprText := "true" + strings.Repeat(" ", maxExpressionChars-len("true"))
		if _, err := compileExpr(exprText, nil); err != nil {
			t.Fatalf("expected boundary-length expression to compile, got error: %v", err)
		}
	})

	t.Run("max function calls accepted", func(t *testing.T) {
		parts := make([]string, 0, maxExpressionFunctionCalls)
		for i := 0; i < maxExpressionFunctionCalls; i++ {
			parts = append(parts, `len("abc") == 3`)
		}
		exprText := strings.Join(parts, " || ")
		if _, err := compileExpr(exprText, nil); err != nil {
			t.Fatalf("expected boundary-function-count expression to compile, got error: %v", err)
		}
	})

	t.Run("max depth accepted", func(t *testing.T) {
		exprText := strings.Repeat("(", maxExpressionDepth) + "true" + strings.Repeat(")", maxExpressionDepth)
		if _, err := compileExpr(exprText, nil); err != nil {
			t.Fatalf("expected boundary-depth expression to compile, got error: %v", err)
		}
	})
}

func TestCompileExprRejectsOnBounds(t *testing.T) {
	cases := []struct {
		name       string
		expression string
		wantErr    string
	}{
		{
			name:       "too many chars",
			expression: strings.Repeat("a", maxExpressionChars+1),
			wantErr:    "exceeds max chars",
		},
		{
			name: "too many function calls",
			expression: func() string {
				parts := make([]string, 0, maxExpressionFunctionCalls+1)
				for i := 0; i < maxExpressionFunctionCalls+1; i++ {
					parts = append(parts, `len("abc") == 3`)
				}
				return strings.Join(parts, " || ")
			}(),
			wantErr: "exceeds max function calls",
		},
		{
			name:       "too deep",
			expression: strings.Repeat("(", maxExpressionDepth+1) + "true" + strings.Repeat(")", maxExpressionDepth+1),
			wantErr:    "exceeds max nesting depth",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileExpr(tc.expression, nil)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestNewEngineIncludesRuleIDOnBoundsError(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Rules: []Rule{
			{
				ID: "deny-over-complex",
				Match: Match{
					Tool: "*",
					When: strings.Repeat("(", maxExpressionDepth+1) + "true" + strings.Repeat(")", maxExpressionDepth+1),
				},
				Effect: "deny",
			},
		},
	}

	_, err := NewEngine(doc, "v-test")
	if err == nil {
		t.Fatalf("expected bounds error from NewEngine")
	}
	if !strings.Contains(err.Error(), `rule "deny-over-complex"`) {
		t.Fatalf("expected actionable error with rule id, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds max nesting depth") {
		t.Fatalf("expected actionable reason, got: %v", err)
	}
}

func TestCompileExprRejectsUnknownSymbolsInPolicyEnv(t *testing.T) {
	doc := &Doc{DefaultEffect: "deny"}
	env := evalEnv(doc, nil)

	if _, err := compileExpr("amount > 10 && purpose(\"refund\")", env); err != nil {
		t.Fatalf("expected known aliases/helpers to compile, got: %v", err)
	}
	if _, err := compileExpr("mystery_symbol > 0", env); err == nil {
		t.Fatal("expected unknown symbol compile error")
	}
}
