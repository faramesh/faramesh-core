// Package artifactverify implements file digest manifests and Ed25519 signatures for supply-chain checks.
package artifactverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestV1 lists expected SHA-256 digests for paths relative to BaseDir.
type ManifestV1 struct {
	Version   int              `json:"version"`
	Artifacts []ArtifactDigest `json:"artifacts"`
}

// ArtifactDigest is one file path and expected lowercase hex SHA-256.
type ArtifactDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LoadManifestJSON parses a JSON manifest from raw bytes.
func LoadManifestJSON(b []byte) (*ManifestV1, error) {
	var m ManifestV1
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest json: %w", err)
	}
	if m.Version != 0 && m.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if len(m.Artifacts) == 0 {
		return nil, fmt.Errorf("empty artifacts")
	}
	return &m, nil
}

// VerifyManifest checks every artifact under baseDir (cleaned, joined).
func VerifyManifest(baseDir string, m *ManifestV1) error {
	baseDir = filepath.Clean(baseDir)
	var errs []string
	for _, a := range m.Artifacts {
		p := filepath.Clean(a.Path)
		if p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
			errs = append(errs, fmt.Sprintf("%q: invalid path", a.Path))
			continue
		}
		full := filepath.Join(baseDir, p)
		got, err := FileSHA256Hex(full)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", a.Path, err))
			continue
		}
		want := strings.ToLower(strings.TrimSpace(a.SHA256))
		if want != got {
			errs = append(errs, fmt.Sprintf("%s: sha256 mismatch (want %s got %s)", a.Path, want, got))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// FileSHA256Hex returns lowercase hex SHA-256 of file contents.
func FileSHA256Hex(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// BytesSHA256Hex returns lowercase hex SHA-256 of b.
func BytesSHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// BuildManifestV1 builds a version-1 manifest from absolute or relative file paths.
// Paths in the manifest are relative to baseDir; every file must be under baseDir.
func BuildManifestV1(baseDir string, filePaths []string) (*ManifestV1, error) {
	baseDir = filepath.Clean(baseDir)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	var arts []ArtifactDigest
	for _, p := range filePaths {
		absFile, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(absBase, absFile)
		if err != nil {
			return nil, err
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("file %q is not under base-dir %q", p, baseDir)
		}
		h, err := FileSHA256Hex(absFile)
		if err != nil {
			return nil, err
		}
		arts = append(arts, ArtifactDigest{Path: filepath.ToSlash(rel), SHA256: h})
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].Path < arts[j].Path })
	return &ManifestV1{Version: 1, Artifacts: arts}, nil
}

// MarshalManifestJSONPretty returns indented JSON for a manifest.
func MarshalManifestJSONPretty(m *ManifestV1) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
