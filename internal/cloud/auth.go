// Package cloud handles authentication with Faramesh Horizon cloud services.
// Tokens are stored in ~/.faramesh/auth.json (mode 0600).
//
// Authentication flow:
//  1. faramesh login → open browser to https://app.faramesh.io/auth/device
//     or prompt for API token
//  2. On success: store token + org info in ~/.faramesh/auth.json
//  3. Core instances read the token and stream DPR records to Horizon when
//     --sync-horizon is set
package cloud

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// HorizonBaseURL is the default Faramesh Horizon API base URL.
	HorizonBaseURL = "https://api.faramesh.io"

	// AuthFileName is the credentials file name in the faramesh config dir.
	AuthFileName = "auth.json"
)

// TokenInfo holds the stored authentication state.
type TokenInfo struct {
	Token      string    `json:"token"`
	OrgID      string    `json:"org_id"`
	OrgName    string    `json:"org_name"`
	UserEmail  string    `json:"user_email"`
	HorizonURL string    `json:"horizon_url"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// IsExpired reports whether the token has expired.
func (t *TokenInfo) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false // non-expiring tokens
	}
	return time.Now().After(t.ExpiresAt)
}

// ConfigDir returns the Faramesh configuration directory (~/.faramesh).
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, ".faramesh"), nil
}

// AuthFile returns the path to the auth credentials file.
func AuthFile() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, AuthFileName), nil
}

// SaveToken writes the token to the auth file (mode 0600).
func SaveToken(info *TokenInfo) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	authFile := filepath.Join(dir, AuthFileName)

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth info: %w", err)
	}
	// Write to temp file, then atomic rename to avoid partial writes.
	tmp := authFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write auth file: %w", err)
	}
	return os.Rename(tmp, authFile)
}

// LoadToken reads the stored token from the auth file.
// Returns (nil, nil) if no token is stored.
func LoadToken() (*TokenInfo, error) {
	authFile, err := AuthFile()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(authFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	var info TokenInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("parse auth file: %w", err)
	}
	return &info, nil
}

// DeleteToken removes the stored token (logout).
func DeleteToken() error {
	authFile, err := AuthFile()
	if err != nil {
		return err
	}
	if err := os.Remove(authFile); os.IsNotExist(err) {
		return nil // already gone
	} else {
		return err
	}
}

// IsAuthenticated reports whether the user has a valid stored token.
func IsAuthenticated() bool {
	info, err := LoadToken()
	if err != nil || info == nil {
		return false
	}
	return !info.IsExpired()
}
