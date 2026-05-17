package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/faramesh/faramesh-core/internal/artifactverify"
	"github.com/faramesh/faramesh-core/internal/hub"
	"github.com/faramesh/faramesh-core/internal/provider/launcher"
)

// ProviderDownload describes one platform artifact.
type ProviderDownload struct {
	URL       string `json:"url"`
	SHA256Hex string `json:"sha256_hex"`
	Size      int64  `json:"size,omitempty"`
}

// ProviderVersionResponse is returned by GET /v1/providers/{name}/versions/{version}.
type ProviderVersionResponse struct {
	APIVersion   string                      `json:"api_version"`
	Kind         string                      `json:"kind"`
	Name         string                      `json:"name"`
	Version      string                      `json:"version"`
	TrustTier    string                      `json:"trust_tier,omitempty"`
	Capabilities []string                    `json:"capabilities,omitempty"`
	Downloads    map[string]ProviderDownload `json:"downloads"`
	Signature    *hub.PackSignature          `json:"signature,omitempty"`
}

// FetchProviderVersion loads a provider manifest from the registry HTTP API.
func (c *Client) FetchProviderVersion(ctx context.Context, ref Ref) (*ProviderVersionResponse, error) {
	if c == nil || c.Hub == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	if ref.Kind != KindProvider {
		return nil, fmt.Errorf("ref is not a provider import")
	}
	base := c.Hub.BaseURL.String()
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + ref.APIPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Hub.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("provider manifest: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var pv ProviderVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&pv); err != nil {
		return nil, err
	}
	return &pv, nil
}

// PlatformKey returns the registry download map key for this machine (e.g. linux_amd64).
func PlatformKey() string {
	return runtime.GOOS + "_" + runtime.GOARCH
}

// InstallProviderBinary downloads (or copies) the provider binary for ref into stackDir.
func InstallProviderBinary(ctx context.Context, c *Client, ref Ref, stackDir string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("registry client not configured")
	}
	pv, err := c.FetchProviderVersion(ctx, ref)
	if err != nil {
		return "", err
	}
	key := PlatformKey()
	dl, ok := pv.Downloads[key]
	if !ok || strings.TrimSpace(dl.URL) == "" {
		return "", fmt.Errorf("provider %s@%s: no download for %s", ref.Name, ref.Version, key)
	}
	installDir := filepath.Join(stackDir, ".faramesh", "providers", strings.ReplaceAll(ref.Name, "/", "_")+"@"+ref.Version)
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(installDir, "provider")
	if err := fetchProviderArtifact(ctx, dl, binPath); err != nil {
		return "", err
	}
	if want := strings.TrimSpace(dl.SHA256Hex); want != "" {
		sum, err := fileSHA256(binPath)
		if err != nil {
			return "", err
		}
		if sum != strings.ToLower(want) {
			_ = os.Remove(binPath)
			return "", fmt.Errorf("provider %s@%s: sha256 mismatch", ref.Name, ref.Version)
		}
	}
	pubB64 := ""
	if pv.Signature != nil {
		pubB64 = strings.TrimSpace(pv.Signature.PublicKeyPEM)
		if pubB64 == "" {
			pubB64 = strings.TrimSpace(pv.Signature.PublicKeyB64)
		}
	}
	if pubB64 != "" && strings.HasPrefix(pubB64, "-----BEGIN") {
		dir := filepath.Join(stackDir, ".faramesh")
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "registry.pub"), []byte(pubB64), 0o644)
	} else if pubB64 != "" {
		_ = ensureRegistryPublicKey(stackDir, pubB64)
	}
	if err := verifyProviderBinary(binPath, stackDir); err != nil {
		return "", err
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return "", err
	}
	return binPath, nil
}

func fetchProviderArtifact(ctx context.Context, dl ProviderDownload, dest string) error {
	url := strings.TrimSpace(dl.URL)
	if strings.HasPrefix(url, "file://") {
		src := strings.TrimPrefix(url, "file://")
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, b, 0o755); err != nil {
			return err
		}
		if sigBytes, err := os.ReadFile(src + ".sig"); err == nil && len(sigBytes) > 0 {
			_ = os.WriteFile(dest+".sig", sigBytes, 0o644)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download provider: HTTP %d: %s", resp.StatusCode, string(b))
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = os.Remove(dest)
		return err
	}
	return nil
}

func verifyProviderBinary(binaryPath, stackDir string) error {
	return launcher.VerifyBinary(binaryPath, stackDir)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyProviderSignature checks detached Ed25519 over provider bytes when signature metadata is present.
func VerifyProviderSignature(stackDir string, binaryPath string, sig *hub.PackSignature) error {
	if sig == nil || strings.TrimSpace(sig.ValueB64) == "" {
		return nil
	}
	decoded, err := artifactverify.DecodeSignatureArg(sig.ValueB64)
	if err != nil {
		return err
	}
	pubPEM := []byte(strings.TrimSpace(sig.PublicKeyPEM))
	if len(pubPEM) == 0 {
		if env := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_PUBLIC_KEY")); env != "" {
			if b, err := os.ReadFile(env); err == nil {
				pubPEM = b
			} else {
				pubPEM = []byte(env)
			}
		}
	}
	if len(pubPEM) == 0 && stackDir != "" {
		if b, err := os.ReadFile(filepath.Join(stackDir, ".faramesh", "registry.pub")); err == nil {
			pubPEM = b
		}
	}
	if len(pubPEM) == 0 {
		return fmt.Errorf("provider signature present but no registry public key configured")
	}
	return artifactverify.VerifyFileSignature(pubPEM, binaryPath, decoded)
}
