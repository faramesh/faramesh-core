// JSON-RPC line server for StdioGateway tests that emits unsolicited notifications.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

func writeLine(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = os.Stdout.Write(append(b, '\n'))
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}

		if method, _ := raw["method"].(string); method != "" {
			writeLine(map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/progress",
				"params": map[string]any{
					"progressToken": "tok-1",
					"progress":      1,
				},
			})
		}

		if id, ok := raw["id"]; ok {
			writeLine(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]any{"echo": true},
			})
		}
	}
}
