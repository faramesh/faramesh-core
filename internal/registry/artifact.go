// Package registry defines the official Faramesh Registry artifact model and import paths.
// See docs/internal/FARAMESH_REGISTRY_PLATFORM.md for the full platform design.
package registry

import (
	"fmt"
	"strings"
)

const DefaultHost = "registry.faramesh.dev"

// Kind is a mutually exclusive registry artifact type.
type Kind string

const (
	KindProvider  Kind = "providers"
	KindPolicy    Kind = "policies"
	KindFramework Kind = "frameworks"
)

// Ref is a parsed import "registry.faramesh.dev/<kind>/<name>@<version>".
type Ref struct {
	Host    string
	Kind    Kind
	Name    string // e.g. faramesh/stripe or langgraph
	Version string
	Alias   string // optional import alias (policy packs)
}

// ParseImport parses a governance import ref. @latest is rejected.
func ParseImport(ref string) (Ref, error) {
	ref = strings.TrimSpace(ref)
	ref = strings.Trim(ref, `"`)
	if strings.HasSuffix(strings.ToLower(ref), "@latest") {
		return Ref{}, fmt.Errorf("import %q: @latest is not allowed", ref)
	}
	at := strings.LastIndex(ref, "@")
	if at <= 0 {
		return Ref{}, fmt.Errorf("import %q: missing @version pin", ref)
	}
	version := strings.TrimSpace(ref[at+1:])
	pathPart := strings.TrimSpace(ref[:at])
	if version == "" || pathPart == "" {
		return Ref{}, fmt.Errorf("import %q: invalid ref", ref)
	}

	host := DefaultHost
	rest := pathPart
	if strings.Contains(pathPart, "://") {
		parts := strings.SplitN(pathPart, "://", 2)
		if len(parts) != 2 {
			return Ref{}, fmt.Errorf("import %q: invalid URL", ref)
		}
		host = parts[0]
		rest = strings.TrimPrefix(parts[1], "/")
	}

	segments := strings.Split(rest, "/")
	// Bare host prefix: registry.faramesh.dev/frameworks/langgraph
	if len(segments) >= 3 && strings.Contains(segments[0], ".") {
		host = segments[0]
		segments = segments[1:]
	}
	if len(segments) < 2 {
		return Ref{}, fmt.Errorf("import %q: expected <kind>/<name>", ref)
	}
	kind := Kind(segments[0])
	switch kind {
	case KindProvider, KindPolicy, KindFramework:
	default:
		return Ref{}, fmt.Errorf("import %q: unknown kind %q (want providers, policies, or frameworks)", ref, segments[0])
	}
	name := strings.Join(segments[1:], "/")
	if name == "" {
		return Ref{}, fmt.Errorf("import %q: missing artifact name", ref)
	}
	return Ref{Host: host, Kind: kind, Name: name, Version: version}, nil
}

// APIPath returns the registry HTTP path for this artifact version (v1).
func (r Ref) APIPath() string {
	encName := strings.ReplaceAll(r.Name, "/", "%2F")
	return fmt.Sprintf("v1/%s/%s/versions/%s", r.Kind, encName, r.Version)
}

// ImportLine returns the canonical import string for documentation/snippets.
func (r Ref) ImportLine() string {
	return fmt.Sprintf(`import "%s/%s/%s@%s"`, r.Host, r.Kind, r.Name, r.Version)
}

// HubPackName is the wire name passed to GET /v1/packs/{name}/versions/{version} until kind-specific routes are live.
func (r Ref) HubPackName() string {
	if strings.Contains(r.Name, "/") {
		return r.Name
	}
	return "faramesh/" + r.Name
}
