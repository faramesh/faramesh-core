package mcp

import (
	"encoding/json"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/postcondition"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// applyPostScanMCPMessage runs post_rules on textual tool output embedded in an
// MCP tools/call JSON-RPC result. Non-text or empty output is left unchanged.
func applyPostScanMCPMessage(p *core.Pipeline, toolID string, msg MCPMessage) MCPMessage {
	if msg.Error != nil || len(msg.Result) == 0 {
		return msg
	}
	text := extractToolResultText(msg.Result)
	if text == "" {
		return msg
	}
	sr := p.ScanOutput(toolID, text)
	switch sr.Outcome {
	case postcondition.OutcomeDenied:
		return MCPMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error: &MCPError{
				Code:    -32003,
				Message: "Faramesh post-scan: " + sr.Reason,
				Data: map[string]any{
					"reason_code": reasons.Normalize(sr.ReasonCode),
				},
			},
		}
	case postcondition.OutcomeRedacted, postcondition.OutcomeWarned:
		if sr.Output != text {
			msg.Result = rebuildMCPResultWithText(msg.Result, sr.Output)
		}
		return msg
	default:
		return msg
	}
}

func extractToolResultText(result json.RawMessage) string {
	var top map[string]any
	if err := json.Unmarshal(result, &top); err != nil {
		return strings.TrimSpace(string(result))
	}
	if content, ok := top["content"].([]any); ok {
		var b strings.Builder
		for _, item := range content {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := m["text"].(string); t != "" {
				b.WriteString(t)
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	if inner, ok := top["result"].(map[string]any); ok {
		raw, err := json.Marshal(inner)
		if err == nil {
			return extractToolResultText(raw)
		}
	}
	out, err := json.Marshal(top)
	if err != nil {
		return ""
	}
	return string(out)
}

func rebuildMCPResultWithText(original json.RawMessage, newText string) json.RawMessage {
	var top map[string]any
	if err := json.Unmarshal(original, &top); err != nil {
		return mustJSON(map[string]any{
			"content": []any{map[string]any{"type": "text", "text": newText}},
		})
	}
	if content, ok := top["content"].([]any); ok && len(content) > 0 {
		if m0, ok := content[0].(map[string]any); ok {
			m0["text"] = newText
			content[0] = m0
			top["content"] = content
			return mustJSON(top)
		}
	}
	return mustJSON(map[string]any{
		"content": []any{map[string]any{"type": "text", "text": newText}},
	})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// transformSSEDataLineForPostScan rewrites one SSE line when it is a `data:` line whose
// payload is a JSON-RPC MCP message with a result. Applies the same logic as
// applyPostScanMCPMessage. Other lines (event:, comments, non-JSON data) pass through.
func transformSSEDataLineForPostScan(line []byte, toolID string, p *core.Pipeline) []byte {
	s := string(line)
	trimLeft := strings.TrimLeft(s, " \t")
	if !strings.HasPrefix(trimLeft, "data:") {
		return line
	}
	leadLen := len(s) - len(trimLeft)
	lead := s[:leadLen]
	payload := strings.TrimSpace(trimLeft[len("data:"):])
	if payload == "" {
		return line
	}
	var msg MCPMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return line
	}
	newMsg := applyPostScanMCPMessage(p, toolID, msg)
	out, err := json.Marshal(newMsg)
	if err != nil {
		return line
	}
	return []byte(lead + "data: " + string(out))
}
