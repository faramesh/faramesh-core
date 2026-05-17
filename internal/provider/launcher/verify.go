package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/artifactverify"
)

// VerifyBinary checks an optional Ed25519 signature file adjacent to the provider binary.
// Signature path: <binary>.sig. Public key PEM: FARAMESH_REGISTRY_PUBLIC_KEY env or registry.pub in stack dir.
func VerifyBinary(binaryPath, stackDir string) error {
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return fmt.Errorf("empty provider binary path")
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("provider binary: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("provider source %q is a directory", binaryPath)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("provider binary %q is not executable", binaryPath)
	}

	sigPath := binaryPath + ".sig"
	sigBytes, err := os.ReadFile(sigPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	sig, err := artifactverify.DecodeSignatureArg(string(sigBytes))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	pubPEM, err := loadRegistryPublicKey(stackDir)
	if err != nil {
		return err
	}
	if err := artifactverify.VerifyFileSignature(pubPEM, binaryPath, sig); err != nil {
		return fmt.Errorf("provider binary signature: %w", err)
	}
	return nil
}

func loadRegistryPublicKey(stackDir string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_PUBLIC_KEY")); env != "" {
		if b, err := os.ReadFile(env); err == nil {
			return b, nil
		}
		return []byte(env), nil
	}
	if stackDir != "" {
		p := filepath.Join(stackDir, ".faramesh", "registry.pub")
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("registry public key not found (set FARAMESH_REGISTRY_PUBLIC_KEY or .faramesh/registry.pub)")
}
