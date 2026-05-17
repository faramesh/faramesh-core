package builtin

import (
	"fmt"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

// NewServer returns an in-process ProviderServiceServer for a built-in type.
func NewServer(providerType string, config map[string]string) (providerv1.ProviderServiceServer, error) {
	typ := strings.ToLower(strings.TrimSpace(providerType))
	switch typ {
	case "vault":
		addr := config["addr"]
		token := config["token"]
		mount := config["mount"]
		if mount == "" {
			mount = "secret"
		}
		broker := credential.NewVaultBroker(credential.VaultConfig{
			Addr:      addr,
			Token:     token,
			MountPath: mount,
			Namespace: config["namespace"],
		})
		return &secretsServer{broker: broker, required: []string{"addr", "token"}, displayType: typ}, nil
	case "aws-sm", "aws_secrets_manager", "aws":
		region := config["region"]
		broker := credential.NewAWSSecretsBroker(credential.AWSSecretsConfig{Region: region})
		return &secretsServer{broker: broker, required: []string{"region"}, displayType: typ}, nil
	case "gcp-sm", "gcp_secret_manager", "gcp":
		project := config["project"]
		broker := credential.NewGCPSecretsBroker(credential.GCPSecretsConfig{Project: project})
		return &secretsServer{broker: broker, required: []string{"project"}, displayType: typ}, nil
	case "azure-kv", "azure_key_vault", "azure":
		broker := credential.NewAzureKeyVaultBroker(credential.AzureKeyVaultConfig{
			VaultURL:     config["vault_url"],
			TenantID:     config["tenant_id"],
			ClientID:     config["client_id"],
			ClientSecret: config["client_secret"],
		})
		return &secretsServer{broker: broker, required: []string{"vault_url"}, displayType: typ}, nil
	case "env":
		return &secretsServer{broker: &credential.EnvBroker{}, required: nil, displayType: typ}, nil
	case "audit-sink", "audit_sink", "siem":
		return newAuditSinkServer(), nil
	case "cost", "cost-estimator":
		return newCostServer(), nil
	case "kms", "kms-dev", "dev-kms":
		return newKMSServer()
	case "slow-init", "slow_init":
		return newSlowInitServer(2 * time.Second), nil
	default:
		return nil, fmt.Errorf("unknown built-in provider type %q", providerType)
	}
}
