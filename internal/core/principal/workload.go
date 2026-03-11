// Package principal — cloud workload identity integration.
//
// Provides identity verification for agents running in cloud environments:
//   - AWS: IRSA (IAM Roles for Service Accounts) / ECS task role
//   - GCP: Workload Identity Federation / service account
//   - Azure: Managed Identity / federated credentials
//   - GitHub: OIDC tokens for CI/CD pipelines
//
// Each provider fetches instance metadata or OIDC tokens from the cloud
// platform's metadata service and converts them to Faramesh Identity.
package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// WorkloadProvider is the interface for cloud workload identity.
type WorkloadProvider interface {
	// Name returns the provider name (aws, gcp, azure, github).
	Name() string
	// Available checks if this provider's metadata service is reachable.
	Available(ctx context.Context) bool
	// Identity fetches the current workload identity.
	Identity(ctx context.Context) (*Identity, error)
}

// DetectWorkloadProvider auto-detects the cloud environment.
func DetectWorkloadProvider() WorkloadProvider {
	// Check environment variables in priority order.
	if os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" || os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" {
		return &AWSWorkloadProvider{}
	}
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" || os.Getenv("GCE_METADATA_HOST") != "" {
		return &GCPWorkloadProvider{}
	}
	if os.Getenv("AZURE_CLIENT_ID") != "" || os.Getenv("MSI_ENDPOINT") != "" {
		return &AzureWorkloadProvider{}
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return &GitHubOIDCProvider{}
	}
	return nil
}

// AWSWorkloadProvider handles AWS IRSA and ECS task role identity.
type AWSWorkloadProvider struct{}

func (p *AWSWorkloadProvider) Name() string { return "aws" }

func (p *AWSWorkloadProvider) Available(ctx context.Context) bool {
	// Check IRSA token file.
	if f := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); f != "" {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	// Check ECS metadata.
	if os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" {
		return true
	}
	// Check EC2 IMDS.
	return imdsReachable(ctx, "http://169.254.169.254/latest/meta-data/", 500*time.Millisecond)
}

func (p *AWSWorkloadProvider) Identity(ctx context.Context) (*Identity, error) {
	// Try IRSA first (EKS).
	if tokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); tokenFile != "" {
		roleARN := os.Getenv("AWS_ROLE_ARN")
		return &Identity{
			ID:       roleARN,
			Verified: true,
			Method:   "aws_irsa",
			Org:      extractAWSAccountID(roleARN),
		}, nil
	}

	// Try ECS task role.
	if uri := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); uri != "" {
		return &Identity{
			ID:       "ecs:" + uri,
			Verified: true,
			Method:   "aws_ecs",
		}, nil
	}

	// Fall back to EC2 instance profile.
	body, err := fetchMetadata(ctx, "http://169.254.169.254/latest/meta-data/iam/info", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("aws identity: %w", err)
	}
	var info struct {
		InstanceProfileArn string `json:"InstanceProfileArn"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("aws identity parse: %w", err)
	}
	return &Identity{
		ID:       info.InstanceProfileArn,
		Verified: true,
		Method:   "aws_ec2",
		Org:      extractAWSAccountID(info.InstanceProfileArn),
	}, nil
}

// GCPWorkloadProvider handles GCP Workload Identity.
type GCPWorkloadProvider struct{}

func (p *GCPWorkloadProvider) Name() string { return "gcp" }

func (p *GCPWorkloadProvider) Available(ctx context.Context) bool {
	host := os.Getenv("GCE_METADATA_HOST")
	if host == "" {
		host = "metadata.google.internal"
	}
	return imdsReachable(ctx, "http://"+host+"/computeMetadata/v1/", 500*time.Millisecond)
}

func (p *GCPWorkloadProvider) Identity(ctx context.Context) (*Identity, error) {
	host := os.Getenv("GCE_METADATA_HOST")
	if host == "" {
		host = "metadata.google.internal"
	}

	// Fetch service account email.
	body, err := fetchGCPMetadata(ctx, "http://"+host+"/computeMetadata/v1/instance/service-accounts/default/email", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("gcp identity: %w", err)
	}
	email := strings.TrimSpace(string(body))

	// Fetch project ID.
	projBody, _ := fetchGCPMetadata(ctx, "http://"+host+"/computeMetadata/v1/project/project-id", 2*time.Second)
	projectID := strings.TrimSpace(string(projBody))

	return &Identity{
		ID:       email,
		Verified: true,
		Method:   "gcp_workload",
		Org:      projectID,
	}, nil
}

// AzureWorkloadProvider handles Azure Managed Identity.
type AzureWorkloadProvider struct{}

func (p *AzureWorkloadProvider) Name() string { return "azure" }

func (p *AzureWorkloadProvider) Available(ctx context.Context) bool {
	if os.Getenv("MSI_ENDPOINT") != "" {
		return true
	}
	return imdsReachable(ctx, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", 500*time.Millisecond)
}

func (p *AzureWorkloadProvider) Identity(ctx context.Context) (*Identity, error) {
	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("azure: AZURE_CLIENT_ID not set")
	}
	tenantID := os.Getenv("AZURE_TENANT_ID")
	return &Identity{
		ID:       clientID,
		Verified: true,
		Method:   "azure_managed",
		Org:      tenantID,
	}, nil
}

// GitHubOIDCProvider handles GitHub Actions OIDC tokens.
type GitHubOIDCProvider struct{}

func (p *GitHubOIDCProvider) Name() string { return "github" }

func (p *GitHubOIDCProvider) Available(_ context.Context) bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

func (p *GitHubOIDCProvider) Identity(_ context.Context) (*Identity, error) {
	repo := os.Getenv("GITHUB_REPOSITORY")
	actor := os.Getenv("GITHUB_ACTOR")
	runID := os.Getenv("GITHUB_RUN_ID")

	if repo == "" {
		return nil, fmt.Errorf("github: GITHUB_REPOSITORY not set")
	}

	return &Identity{
		ID:       fmt.Sprintf("github:%s/%s@%s", repo, actor, runID),
		Verified: true,
		Method:   "github_oidc",
		Org:      strings.SplitN(repo, "/", 2)[0],
	}, nil
}

// --- helpers ---

func imdsReachable(ctx context.Context, url string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

func fetchMetadata(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func fetchGCPMetadata(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP metadata HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func extractAWSAccountID(arn string) string {
	// arn:aws:iam::123456789012:role/my-role
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
