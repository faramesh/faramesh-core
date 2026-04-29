package hub

import (
	"path/filepath"
	"testing"
)

func TestPackStatus_sidecarsAndManifest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:        "acme/demo",
		Version:     "1.0.0",
		PolicyYAML:  "version: 1\npolicy: {}\n",
		PolicyFPL:   "pack acme/demo\n",
		TrustTier:   "verified",
		Description: "d",
	}
	if _, err := WritePackToDiskWithMode(root, p, "shadow"); err != nil {
		t.Fatal(err)
	}
	st, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed {
		t.Fatal("expected installed")
	}
	if st.AppliedMode != "shadow" {
		t.Fatalf("applied_mode: got %q want shadow", st.AppliedMode)
	}
	if st.TrustTier != "verified" {
		t.Fatalf("trust_tier: got %q want verified", st.TrustTier)
	}
	dir := PackInstallDir(root, p.Name, p.Version)
	wantFPL := filepath.Join(dir, "policy.fpl")
	if st.PolicyFPLPath != wantFPL {
		t.Fatalf("policy_fpl_path: got %q want %q", st.PolicyFPLPath, wantFPL)
	}
	wantCmp := filepath.Join(dir, compiledPolicyFile)
	if st.PolicyCompiledPath != wantCmp {
		t.Fatalf("policy_compiled_path: got %q want %q", st.PolicyCompiledPath, wantCmp)
	}
}

func TestPackStatus_noFPL(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:       "acme/nofpl",
		Version:    "0.1.0",
		PolicyYAML: "version: 1\npolicy: {}\n",
	}
	if _, err := WritePackToDiskWithMode(root, p, "enforce"); err != nil {
		t.Fatal(err)
	}
	st, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if st.PolicyFPLPath != "" {
		t.Fatalf("unexpected fpl path: %q", st.PolicyFPLPath)
	}
	if st.PolicyCompiledPath == "" {
		t.Fatal("expected compiled policy path")
	}
}

func TestSetInstalledPackMode_shadowThenEnforce(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:       "acme/mode",
		Version:    "2.0.0",
		PolicyYAML: "version: 1\npolicy: {}\n",
	}
	if _, err := WritePackToDiskWithMode(root, p, "shadow"); err != nil {
		t.Fatal(err)
	}
	if err := SetInstalledPackMode(root, p.Name, p.Version, "enforce"); err != nil {
		t.Fatal(err)
	}
	st, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if st.AppliedMode != "enforce" {
		t.Fatalf("after enforce: got %q", st.AppliedMode)
	}
	if err := SetInstalledPackMode(root, p.Name, p.Version, "shadow"); err != nil {
		t.Fatal(err)
	}
	st2, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if st2.AppliedMode != "shadow" {
		t.Fatalf("after shadow: got %q", st2.AppliedMode)
	}
}

func TestPackStatus_disabledStillShowsPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := &PackVersionResponse{
		Name:       "acme/dis",
		Version:    "1.0.0",
		PolicyYAML: "version: 1\npolicy: {}\n",
		PolicyFPL:  "x",
	}
	if _, err := WritePackToDiskWithMode(root, p, "enforce"); err != nil {
		t.Fatal(err)
	}
	if _, err := DisableInstalledPack(root, p.Name, p.Version, "test", nil); err != nil {
		t.Fatal(err)
	}
	st, err := PackStatus(root, p.Name, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Disabled {
		t.Fatal("expected disabled")
	}
	if st.PolicyCompiledPath == "" {
		t.Fatal("expected compiled path when disabled")
	}
}

func TestPackStatus_notInstalled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	st, err := PackStatus(root, "none/here", "9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if st.Installed {
		t.Fatal("expected not installed")
	}
}
