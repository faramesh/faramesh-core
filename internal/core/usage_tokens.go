package core

import (
	"encoding/json"
	"fmt"
)

// UsageTokensFromArgs extracts reported LLM/token usage from canonical tool args.
// Adapters or agents may set:
//   - _faramesh.tokens (number)
//   - usage_tokens (number)
//   - _faramesh nested map key "tokens"
//
// Values must be non-negative. Non-numeric values are ignored.
func UsageTokensFromArgs(args map[string]any) int64 {
	if args == nil {
		return 0
	}
	if n := anyToInt64(args["_faramesh.tokens"]); n > 0 {
		return n
	}
	if n := anyToInt64(args["usage_tokens"]); n > 0 {
		return n
	}
	if raw, ok := args["_faramesh"]; ok {
		if m, ok := raw.(map[string]any); ok {
			if n := anyToInt64(m["tokens"]); n > 0 {
				return n
			}
		}
	}
	return 0
}

func anyToInt64(v any) int64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		if x > 1<<63-1 {
			return 0
		}
		return int64(x)
	case float64:
		if x < 0 || x > float64(1<<62) {
			return 0
		}
		return int64(x)
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0
		}
		if i < 0 {
			return 0
		}
		return i
	case string:
		var i int64
		_, err := fmt.Sscan(x, &i)
		if err != nil || i < 0 {
			return 0
		}
		return i
	default:
		return 0
	}
}
