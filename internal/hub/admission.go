package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type InstallAdmissionFinding struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type InstallAdmissionResult struct {
	Allowed  bool                      `json:"allowed"`
	Findings []InstallAdmissionFinding `json:"findings,omitempty"`
}

type QuarantineManifest struct {
	PackName    string                    `json:"pack_name"`
	PackVersion string                    `json:"pack_version"`
	Reason      string                    `json:"reason"`
	Findings    []InstallAdmissionFinding `json:"findings,omitempty"`
	CreatedAt   string                    `json:"created_at"`
}

var (
	reNullByte           = regexp.MustCompile(`\x00`)
	reTraversal          = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%252e%252e)`)
	reDestructiveCommand = regexp.MustCompile(`(?i)(rm\s+-rf\s+/|mkfs\.|:\(\)\s*\{\s*:\|:\s*&\s*\};:)`)
	reSecretToken        = regexp.MustCompile(`(?i)(sk_live_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})`)
)

const maxAdmissionPolicyBytes = 1 << 20

// InstallAdmissionOptions toggles optional release-gate checks beyond static policy scanning.
type InstallAdmissionOptions struct {
	// RequireVerifiedPublisher rejects packs whose publisher block is missing or verified=false.
	RequireVerifiedPublisher bool
}

func EvaluateInstallAdmission(p *PackVersionResponse) InstallAdmissionResult {
	return EvaluateInstallAdmissionWithOptions(p, InstallAdmissionOptions{})
}

func EvaluateInstallAdmissionWithOptions(p *PackVersionResponse, opts InstallAdmissionOptions) InstallAdmissionResult {
	if p == nil {
		return InstallAdmissionResult{Allowed: false, Findings: []InstallAdmissionFinding{{ID: "nil_pack", Message: "pack payload is nil"}}}
	}

	findings := make([]InstallAdmissionFinding, 0)
	name := strings.TrimSpace(p.Name)
	policy := p.PolicyYAML
	if len(policy) > maxAdmissionPolicyBytes {
		findings = append(findings, InstallAdmissionFinding{
			ID:      "policy_oversize",
			Message: fmt.Sprintf("policy payload exceeds %d bytes", maxAdmissionPolicyBytes),
		})
	}

	if blocked := blockedByList(name, os.Getenv("FARAMESH_HUB_BLOCKLIST")); blocked {
		findings = append(findings, InstallAdmissionFinding{
			ID:      "pack_blocklisted",
			Message: fmt.Sprintf("pack %q is present in FARAMESH_HUB_BLOCKLIST", name),
		})
	}
	if !allowedByList(name, os.Getenv("FARAMESH_HUB_ALLOWLIST")) {
		findings = append(findings, InstallAdmissionFinding{
			ID:      "pack_not_allowlisted",
			Message: fmt.Sprintf("pack %q is not present in FARAMESH_HUB_ALLOWLIST", name),
		})
	}

	if reNullByte.MatchString(policy) {
		findings = append(findings, InstallAdmissionFinding{ID: "policy_null_byte", Message: "policy contains null-byte payload"})
	}
	if reTraversal.MatchString(policy) {
		findings = append(findings, InstallAdmissionFinding{ID: "policy_path_traversal", Message: "policy contains path traversal pattern"})
	}
	if reDestructiveCommand.MatchString(policy) {
		findings = append(findings, InstallAdmissionFinding{ID: "policy_destructive_command", Message: "policy contains destructive command pattern"})
	}
	if reSecretToken.MatchString(policy) {
		findings = append(findings, InstallAdmissionFinding{ID: "policy_embedded_secret", Message: "policy appears to embed a secret token"})
	}

	if opts.RequireVerifiedPublisher {
		pub := p.Publisher
		if pub == nil || strings.TrimSpace(pub.ID) == "" {
			findings = append(findings, InstallAdmissionFinding{
				ID:      "publisher_missing",
				Message: "pack has no publisher identity; registry must attest publisher for verified installs",
			})
		} else if !pub.Verified {
			label := strings.TrimSpace(pub.DisplayName)
			if label == "" {
				label = pub.ID
			}
			findings = append(findings, InstallAdmissionFinding{
				ID:      "publisher_unverified",
				Message: fmt.Sprintf("publisher %q is not marked verified by the registry", label),
			})
		}
	}

	return InstallAdmissionResult{Allowed: len(findings) == 0, Findings: findings}
}

func QuarantinePack(root string, p *PackVersionResponse, reason string, findings []InstallAdmissionFinding) (string, error) {
	if p == nil {
		return "", fmt.Errorf("nil pack")
	}
	dir := PackInstallDir(root, p.Name, p.Version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("mkdir quarantine dir: %w", err)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(p.PolicyYAML), 0o600); err != nil {
		return "", fmt.Errorf("write quarantined policy: %w", err)
	}
	if strings.TrimSpace(p.PolicyFPL) != "" {
		fplPath := filepath.Join(dir, "policy.fpl")
		if err := os.WriteFile(fplPath, []byte(p.PolicyFPL), 0o600); err != nil {
			return "", fmt.Errorf("write quarantined policy.fpl: %w", err)
		}
	}
	if compiled, err := MaterializePolicyCompiledYAML(dir); err == nil {
		_ = os.WriteFile(filepath.Join(dir, compiledPolicyFile), compiled, 0o600)
	}

	manifestPath := filepath.Join(dir, "quarantine.json")
	manifest := QuarantineManifest{
		PackName:    p.Name,
		PackVersion: p.Version,
		Reason:      reason,
		Findings:    findings,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal quarantine manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, b, 0o600); err != nil {
		return "", fmt.Errorf("write quarantine manifest: %w", err)
	}

	return dir, nil
}

func blockedByList(name, raw string) bool {
	entries := parseList(raw)
	for _, entry := range entries {
		if matchesListEntry(entry, name) {
			return true
		}
	}
	return false
}

func allowedByList(name, raw string) bool {
	entries := parseList(raw)
	if len(entries) == 0 {
		return true
	}
	for _, entry := range entries {
		if matchesListEntry(entry, name) {
			return true
		}
	}
	return false
}

func matchesListEntry(entry, value string) bool {
	ent := strings.ToLower(strings.TrimSpace(entry))
	v := strings.ToLower(strings.TrimSpace(value))
	if ent == "" || v == "" {
		return false
	}
	if ent == v {
		return true
	}
	matched, err := path.Match(ent, v)
	if err != nil {
		return false
	}
	return matched
}

func parseList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		v = strings.ToLower(v)
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
