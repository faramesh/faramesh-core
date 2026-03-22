// Minimal JSON-RPC line server for StdioGateway tests: one JSON object per line, same id in response.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		id := raw["id"]
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  map[string]any{"echo": true},
		}
		b, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		_, _ = os.Stdout.Write(append(b, '\n'))
	}
}
