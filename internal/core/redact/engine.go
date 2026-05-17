package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
)

// Engine applies keyed HMAC redaction to CAR args before WAL write.
type Engine struct {
	key   []byte
	rules []agentgov.Redaction
}

func NewEngine(key []byte, rules []agentgov.Redaction) *Engine {
	if len(rules) == 0 || len(key) == 0 {
		return nil
	}
	cp := append([]agentgov.Redaction(nil), rules...)
	return &Engine{key: append([]byte(nil), key...), rules: cp}
}

// Apply returns redacted args or an error (fail-closed).
func (e *Engine) Apply(toolID string, args map[string]any) (map[string]any, error) {
	if e == nil || len(e.rules) == 0 {
		return args, nil
	}
	out := cloneMap(args)
	for _, rule := range e.rules {
		if !toolMatches(rule.Tool, toolID) {
			continue
		}
		for _, p := range rule.Paths {
			if err := e.redactPath(out, p); err != nil {
				return nil, fmt.Errorf("redact path %q: %w", p, err)
			}
		}
	}
	return out, nil
}

func (e *Engine) redactValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, e.key)
	_, _ = mac.Write(b)
	return "hmac:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (e *Engine) redactPath(root map[string]any, dotPath string) error {
	if root == nil {
		return fmt.Errorf("nil args")
	}
	segments := splitPath(dotPath)
	if len(segments) == 0 {
		return fmt.Errorf("empty path")
	}
	return e.redactAt(root, segments, 0)
}

func (e *Engine) redactAt(cur any, segments []string, idx int) error {
	if idx >= len(segments) {
		return nil
	}
	seg := segments[idx]
	switch node := cur.(type) {
	case map[string]any:
		val, ok := node[seg]
		if !ok {
			return fmt.Errorf("missing segment %q", seg)
		}
		if idx == len(segments)-1 {
			hv, err := e.redactValue(val)
			if err != nil {
				return err
			}
			node[seg] = hv
			return nil
		}
		return e.redactAt(val, segments, idx+1)
	default:
		return fmt.Errorf("cannot traverse %q in path", seg)
	}
}

func splitPath(p string) []string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "args.")
	p = strings.Trim(p, ".")
	if p == "" {
		return nil
	}
	return strings.Split(p, ".")
}

func toolMatches(pattern, toolID string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == toolID {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(toolID, strings.TrimSuffix(pattern, "*"))
	}
	if strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, toolID)
		return ok
	}
	return false
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return make(map[string]any)
	}
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = make(map[string]any)
	}
	return out
}
