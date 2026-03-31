package principal

import "testing"

func TestIsTrustedVerificationMethodIDPOIDCProviders(t *testing.T) {
	for _, method := range []string{"okta_oidc", "azure_ad_oidc", "auth0_oidc", "google_oidc", "idp_oidc", "ldap_bind", "idp_local"} {
		if !IsTrustedVerificationMethod(method) {
			t.Fatalf("expected method %q to be trusted", method)
		}
	}
}
