package hub

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWritePackToDisk(t *testing.T) {
	dir := t.TempDir()
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"t\"\n",
		TrustTier:  "verified",
	}
	path, err := WritePackToDisk(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != p.PolicyYAML {
		t.Fatal("policy mismatch")
	}
	man := filepath.Join(filepath.Dir(path), "manifest.json")
	if _, err := os.Stat(man); err != nil {
		t.Fatal(err)
	}
	compiled := filepath.Join(filepath.Dir(path), "policy.compiled.yaml")
	if _, err := os.Stat(compiled); err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(man)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mb), `"policy_compiled_sha256"`) {
		t.Fatalf("expected manifest policy_compiled_sha256: %s", mb)
	}
}

func TestWritePackToDiskWritesPolicyFPL(t *testing.T) {
	dir := t.TempDir()
	fpl := "agent t {\n  default deny\n  rules { deny! shell/run }\n}\n"
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"t\"\n",
		PolicyFPL:  fpl,
		TrustTier:  "verified",
	}
	path, err := WritePackToDisk(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	fplPath := filepath.Join(filepath.Dir(path), "policy.fpl")
	got, err := os.ReadFile(fplPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != fpl {
		t.Fatalf("policy.fpl mismatch")
	}
	manPath := filepath.Join(filepath.Dir(path), "manifest.json")
	mb, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mb), `"policy_fpl_sha256"`) {
		t.Fatalf("expected manifest to include policy_fpl_sha256, got: %s", mb)
	}
	if !strings.Contains(string(mb), `"policy_compiled_sha256"`) {
		t.Fatalf("expected manifest to include policy_compiled_sha256, got: %s", mb)
	}
}

func TestWritePackToDiskWithMode_writesPolicyYamlFPLCompiledAndManifest(t *testing.T) {
	dir := t.TempDir()
	fpl := "agent t {\n  default deny\n  rules { deny! shell/run }\n}\n"
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"t\"\n",
		PolicyFPL:  fpl,
		TrustTier:  "verified",
	}
	policyPath, err := WritePackToDiskWithMode(dir, p, "shadow")
	if err != nil {
		t.Fatal(err)
	}
	packDir := filepath.Dir(policyPath)
	ents, err := os.ReadDir(packDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	want := []string{"manifest.json", "policy.compiled.yaml", "policy.fpl", "policy.yaml"}
	if !slices.Equal(names, want) {
		t.Fatalf("pack dir files = %v, want %v", names, want)
	}
}

func TestWritePackToDiskWithMode_writesYamlCompiledAndManifestWithoutFPL(t *testing.T) {
	dir := t.TempDir()
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"t\"\n",
		TrustTier:  "verified",
	}
	policyPath, err := WritePackToDiskWithMode(dir, p, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	packDir := filepath.Dir(policyPath)
	ents, err := os.ReadDir(packDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	want := []string{"manifest.json", "policy.compiled.yaml", "policy.yaml"}
	if !slices.Equal(names, want) {
		t.Fatalf("pack dir files = %v, want %v", names, want)
	}
	if _, err := os.Stat(filepath.Join(packDir, "policy.fpl")); err == nil {
		t.Fatal("did not expect policy.fpl when PolicyFPL is empty")
	}
}

func TestEvaluateInstallAdmission_DetectsFindings(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "")

	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "tool: shell\nargs: rm -rf /\n",
	}

	res := EvaluateInstallAdmission(p)
	if res.Allowed {
		t.Fatalf("expected admission deny, got allow: %+v", res)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestEvaluateInstallAdmission_RespectsBlockList(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "demo/pack")

	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
	}

	res := EvaluateInstallAdmission(p)
	if res.Allowed {
		t.Fatalf("expected blocklisted pack to be denied: %+v", res)
	}
}

func TestEvaluateInstallAdmission_BlockListWildcard(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "demo/*")

	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
	}

	res := EvaluateInstallAdmission(p)
	if res.Allowed {
		t.Fatalf("expected wildcard blocklisted pack to be denied: %+v", res)
	}
}

func TestEvaluateInstallAdmission_AllowListWildcard(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "demo/*")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "")

	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
	}

	res := EvaluateInstallAdmission(p)
	if !res.Allowed {
		t.Fatalf("expected wildcard allowlisted pack to be allowed: %+v", res)
	}
}

func TestEvaluateInstallAdmission_DetectsOversizedPolicy(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "")

	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: strings.Repeat("a", maxAdmissionPolicyBytes+1),
	}

	res := EvaluateInstallAdmission(p)
	if res.Allowed {
		t.Fatalf("expected oversized payload to be denied: %+v", res)
	}
}

func TestEvaluateInstallAdmissionWithOptions_RequiresVerifiedPublisher(t *testing.T) {
	t.Setenv("FARAMESH_HUB_ALLOWLIST", "")
	t.Setenv("FARAMESH_HUB_BLOCKLIST", "")

	base := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"x\"\n",
	}

	t.Run("missing publisher", func(t *testing.T) {
		res := EvaluateInstallAdmissionWithOptions(base, InstallAdmissionOptions{RequireVerifiedPublisher: true})
		if res.Allowed {
			t.Fatal("expected denial")
		}
	})

	t.Run("unverified", func(t *testing.T) {
		p := *base
		p.Publisher = &PackPublisher{ID: "pub", DisplayName: "Acme", Verified: false}
		res := EvaluateInstallAdmissionWithOptions(&p, InstallAdmissionOptions{RequireVerifiedPublisher: true})
		if res.Allowed {
			t.Fatal("expected denial")
		}
	})

	t.Run("verified ok", func(t *testing.T) {
		p := *base
		p.Publisher = &PackPublisher{ID: "pub", DisplayName: "Acme", Verified: true}
		res := EvaluateInstallAdmissionWithOptions(&p, InstallAdmissionOptions{RequireVerifiedPublisher: true})
		if !res.Allowed {
			t.Fatalf("expected allow: %+v", res)
		}
	})
}

func TestQuarantinePack_WritesManifest(t *testing.T) {
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
	}

	path, err := QuarantinePack(root, p, "install admission failed", []InstallAdmissionFinding{{ID: "x", Message: "bad"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "policy.yaml")); err != nil {
		t.Fatalf("missing quarantined policy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "quarantine.json")); err != nil {
		t.Fatalf("missing quarantine manifest: %v", err)
	}
}

func TestQuarantinePack_WritesFPLAndCompiledWhenPresent(t *testing.T) {
	root := t.TempDir()
	fpl := "agent q {\n  default deny\n  rules { deny! shell/run }\n}\n"
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
		PolicyFPL:  fpl,
	}
	path, err := QuarantinePack(root, p, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "policy.fpl")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "policy.compiled.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestPackDisableEnableLifecycle(t *testing.T) {
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: "faramesh-version: \"1\"\nagent-id: \"t\"\n",
	}
	if _, err := WritePackToDisk(root, p); err != nil {
		t.Fatalf("write pack: %v", err)
	}

	disablePath, err := DisableInstalledPack(root, p.Name, p.Version, "admission failure", []InstallAdmissionFinding{{ID: "risky", Message: "risky pattern"}})
	if err != nil {
		t.Fatalf("disable pack: %v", err)
	}
	if _, err := os.Stat(disablePath); err != nil {
		t.Fatalf("missing disable manifest: %v", err)
	}

	status, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatalf("pack status: %v", err)
	}
	if !status.Installed || !status.Disabled {
		t.Fatalf("unexpected status after disable: %+v", status)
	}
	if status.PolicyCompiledPath == "" {
		t.Fatal("expected policy_compiled_path when disabled")
	}
	if status.DisableFindings != 1 {
		t.Fatalf("disable findings=%d, want 1", status.DisableFindings)
	}

	if err := EnableInstalledPack(root, p.Name, p.Version); err != nil {
		t.Fatalf("enable pack: %v", err)
	}
	status, err = PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatalf("pack status after enable: %v", err)
	}
	if !status.Installed || status.Disabled {
		t.Fatalf("unexpected status after enable: %+v", status)
	}
}

func TestDisableInstalledPack_NotInstalled(t *testing.T) {
	root := t.TempDir()
	_, err := DisableInstalledPack(root, "demo/pack", "1.0.0", "manual", nil)
	if !errors.Is(err, ErrPackNotInstalled) {
		t.Fatalf("expected ErrPackNotInstalled, got %v", err)
	}
}
