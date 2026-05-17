package ast

import "strconv"

// Value is a configuration scalar in provider, runtime, or enforcement blocks.
type Value struct {
	Kind ValueKind

	String  string
	Number  float64
	Bool    bool
	EnvVar  string
	List    []Value
}

type ValueKind string

const (
	ValueString ValueKind = "string"
	ValueNumber ValueKind = "number"
	ValueBool   ValueKind = "bool"
	ValueEnv    ValueKind = "env"
	ValueIdent  ValueKind = "ident"
	ValueList   ValueKind = "list"
)

func StringValue(s string) Value {
	return Value{Kind: ValueString, String: s}
}

func IdentValue(s string) Value {
	return Value{Kind: ValueIdent, String: s}
}

func EnvValue(name string) Value {
	return Value{Kind: ValueEnv, EnvVar: name}
}

func NumberValue(n float64) Value {
	return Value{Kind: ValueNumber, Number: n}
}

func BoolValue(b bool) Value {
	return Value{Kind: ValueBool, Bool: b}
}

// Display returns a human-readable form for diagnostics.
func (v Value) Display() string {
	switch v.Kind {
	case ValueEnv:
		return "env(\"" + v.EnvVar + "\")"
	case ValueString:
		return "\"" + v.String + "\""
	case ValueBool:
		if v.Bool {
			return "true"
		}
		return "false"
	case ValueNumber:
		return formatFloat(v.Number)
	case ValueIdent:
		return v.String
	default:
		return ""
	}
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
