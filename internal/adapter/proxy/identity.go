package proxy

import "net/http"

// ProcessIdentity captures Linux process identity for a proxied request source.
type ProcessIdentity struct {
	PID              int    `json:"pid"`
	Executable       string `json:"executable"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
}

type processIdentityResolver interface {
	Resolve(*http.Request) (*ProcessIdentity, error)
}

type defaultProcessIdentityResolver struct{}

func newProcessIdentityResolver() processIdentityResolver {
	return defaultProcessIdentityResolver{}
}

func (defaultProcessIdentityResolver) Resolve(r *http.Request) (*ProcessIdentity, error) {
	return resolveProcessIdentity(r)
}
