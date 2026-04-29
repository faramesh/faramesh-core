// Package sbom emits CycloneDX-compatible JSON for supply-chain transparency.
// Uses runtime/debug.ReadBuildInfo() so output reflects the built binary's module graph.
package sbom

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CycloneDX BOM subset (JSON) — enough for CI ingestion and SPDX/CycloneDX tooling.
type document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Timestamp string      `json:"timestamp"`
	Tools     []toolEntry `json:"tools"`
	Component *component  `json:"component,omitempty"`
}

type toolEntry struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// GenerateJSON returns CycloneDX 1.5 JSON for the running binary's module dependencies.
func GenerateJSON(mainModulePath, mainModuleVersion string) ([]byte, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf("debug.ReadBuildInfo: not available")
	}
	if mainModulePath == "" {
		mainModulePath = bi.Main.Path
	}
	if mainModuleVersion == "" {
		mainModuleVersion = bi.Main.Version
		if mainModuleVersion == "" {
			mainModuleVersion = "(devel)"
		}
	}

	var comps []component
	seen := make(map[string]struct{})
	add := func(name, ver string) {
		if name == "" {
			return
		}
		key := name + "@" + ver
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		purl := ""
		if strings.HasPrefix(name, "github.com/") || strings.HasPrefix(name, "golang.org/") {
			purl = "pkg:golang/" + strings.ReplaceAll(name, "/", "%2F") + "@" + ver
		}
		comps = append(comps, component{
			Type:    "library",
			Name:    name,
			Version: ver,
			PURL:    purl,
		})
	}

	// In test binaries debug.ReadBuildInfo returns an empty Main.Path and no
	// Deps. Fall back to the explicitly supplied mainModulePath so the BOM is
	// never empty (the test / CI caller can always pass the real module path).
	if bi.Main.Path == "" && mainModulePath == "" {
		mainModulePath = "github.com/faramesh/faramesh-core"
	}
	add(mainModulePath, mainModuleVersion)
	for _, m := range bi.Deps {
		if m.Path == "" {
			continue
		}
		ver := m.Version
		if ver == "" {
			ver = "(unknown)"
		}
		add(m.Path, ver)
	}

	doc := document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuid.NewString(),
		Version:      1,
		Metadata: metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []toolEntry{
				{Vendor: "Faramesh", Name: "faramesh-core", Version: "sbom/1"},
			},
			Component: &component{
				Type:    "application",
				Name:    mainModulePath,
				Version: mainModuleVersion,
			},
		},
		Components: comps,
	}
	return json.MarshalIndent(doc, "", "  ")
}
