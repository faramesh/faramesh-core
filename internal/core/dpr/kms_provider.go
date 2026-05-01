package dpr

import (
	"fmt"
	"sync"
)

// KMSProviderRegistry is a global registry for KMS provider implementations.
// Community contributors can register new providers at init() time.
// Providers are responsible for implementing the Signer interface and handling
// their own configuration/authentication (e.g., from environment, config files, cloud SDKs).
type KMSProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]KMSProviderFactory
}

// KMSProviderFactory constructs a Signer from a URI and optional data dir.
// Implementations MUST be idempotent and safe for concurrent access.
// URI format examples:
//   - file:///path/to/key (local file)
//   - localkms://keyid (local on-prem KMS)
//   - aws-kms://alias/key-alias (AWS KMS — implemented by community provider)
//   - gcp-kms://projects/p/locations/l/keyRings/kr/cryptoKeys/ck (GCP KMS)
//   - azure-kms://vault.azure.net/keys/keyname (Azure Key Vault)
type KMSProviderFactory func(uri, dataDir string) (Signer, error)

var globalKMSRegistry = &KMSProviderRegistry{
	providers: make(map[string]KMSProviderFactory),
}

// RegisterKMSProvider registers a new KMS provider with the global registry.
// Call this during init() in your provider package.
// Example:
//   func init() {
//       dpr.RegisterKMSProvider("aws-kms", NewAWSKMSSigner)
//   }
func RegisterKMSProvider(scheme string, factory KMSProviderFactory) error {
	globalKMSRegistry.mu.Lock()
	defer globalKMSRegistry.mu.Unlock()
	if _, exists := globalKMSRegistry.providers[scheme]; exists {
		return fmt.Errorf("kms provider already registered: %s", scheme)
	}
	globalKMSRegistry.providers[scheme] = factory
	return nil
}

// GetKMSProvider retrieves a registered KMS provider by scheme.
func GetKMSProvider(scheme string) (KMSProviderFactory, bool) {
	globalKMSRegistry.mu.RLock()
	defer globalKMSRegistry.mu.RUnlock()
	factory, ok := globalKMSRegistry.providers[scheme]
	return factory, ok
}

// ConstructSignerFromURI parses a URI and constructs a Signer using the appropriate
// registered provider. Returns an error if the scheme is not registered.
func ConstructSignerFromURI(uri, dataDir string) (Signer, error) {
	// Parse URI scheme
	scheme := extractScheme(uri)
	if scheme == "" {
		return nil, fmt.Errorf("invalid signer uri: %s", uri)
	}
	factory, ok := GetKMSProvider(scheme)
	if !ok {
		return nil, fmt.Errorf("no kms provider registered for scheme: %s", scheme)
	}
	return factory(uri, dataDir)
}

func extractScheme(uri string) string {
	for i := 0; i < len(uri); i++ {
		if uri[i] == ':' {
			return uri[:i]
		}
	}
	return ""
}

// ListRegisteredKMSProviders returns the list of scheme names for registered providers.
func ListRegisteredKMSProviders() []string {
	globalKMSRegistry.mu.RLock()
	defer globalKMSRegistry.mu.RUnlock()
	schemes := make([]string, 0, len(globalKMSRegistry.providers))
	for scheme := range globalKMSRegistry.providers {
		schemes = append(schemes, scheme)
	}
	return schemes
}
