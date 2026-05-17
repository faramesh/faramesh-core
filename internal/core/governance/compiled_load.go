package governance

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadCompiledFromPath reads a compiled artifact by absolute or relative path.
func LoadCompiledFromPath(path string) (*Compiled, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Compiled
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse compiled: %w", err)
	}
	return &c, nil
}
