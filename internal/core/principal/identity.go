package principal

import "strings"

// Identity is the normalized principal/workload identity used by policy eval.
type Identity struct {
	ID       string `json:"id"`
	Tier     string `json:"tier,omitempty"`
	Role     string `json:"role,omitempty"`
	Org      string `json:"org,omitempty"`
	Verified bool   `json:"verified"`
	Method   string `json:"method,omitempty"`
}

var trustedVerificationMethods = map[string]struct{}{
	"spiffe":        {},
	"aws_irsa":      {},
	"aws_ecs":       {},
	"aws_ec2":       {},
	"gcp_workload":  {},
	"azure_managed": {},
	"github_oidc":   {},
}

// IsTrustedVerificationMethod reports whether method is an authoritative source.
func IsTrustedVerificationMethod(method string) bool {
	_, ok := trustedVerificationMethods[strings.ToLower(strings.TrimSpace(method))]
	return ok
}
