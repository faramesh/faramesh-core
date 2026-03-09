// Package embedded holds static assets bundled into the faramesh binary.
package embedded

import _ "embed"

// DemoPolicy is the demo.yaml policy bundled with the binary for faramesh demo.
//
//go:embed demo.yaml
var DemoPolicy []byte
