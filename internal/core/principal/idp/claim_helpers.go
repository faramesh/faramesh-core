package idp

import "strings"

func normalizeBearerToken(token string) string {
	tok := strings.TrimSpace(token)
	if len(tok) >= len("bearer ") && strings.EqualFold(tok[:len("bearer ")], "bearer ") {
		return strings.TrimSpace(tok[len("bearer "):])
	}
	return tok
}

func claimString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case string:
			if s := strings.TrimSpace(typed); s != "" {
				return s
			}
		case []any:
			for _, entry := range typed {
				if s, ok := entry.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}
