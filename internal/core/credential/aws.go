package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AWSSecretsConfig configures the AWS Secrets Manager broker.
type AWSSecretsConfig struct {
	Region    string
	Endpoint  string // override for testing/localstack
	AccessKey string // falls back to default credential chain
	SecretKey string
	Timeout   time.Duration
}

func (c *AWSSecretsConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
}

// NewAWSSecretsBroker creates a production AWS Secrets Manager broker.
func NewAWSSecretsBroker(cfg AWSSecretsConfig) *AWSSecretsBroker {
	cfg.defaults()
	return &AWSSecretsBroker{
		Region: cfg.Region,
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (b *AWSSecretsBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}

	secretID := resolveAWSSecretID(req)
	endpoint := b.resolveEndpoint()
	url := fmt.Sprintf("%s/?Action=GetSecretValue&SecretId=%s&Version=2017-10-17", endpoint, secretID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("aws secrets: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpReq.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("aws secrets: request %s: %w", secretID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws secrets: %s returned %d: %s", secretID, resp.StatusCode, truncate(string(body), 200))
	}

	var result awsSecretResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("aws secrets: parse response: %w", err)
	}

	value := result.SecretString
	if value == "" {
		return nil, fmt.Errorf("aws secrets: empty secret at %s", secretID)
	}

	return &Credential{
		Value:     value,
		Source:    "aws_secrets_manager",
		Scope:     req.Scope,
		Revocable: false,
	}, nil
}

func (b *AWSSecretsBroker) resolveEndpoint() string {
	if b.cfg.Endpoint != "" {
		return b.cfg.Endpoint
	}
	return fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", b.cfg.Region)
}

func resolveAWSSecretID(req FetchRequest) string {
	if req.Scope != "" {
		return req.Scope
	}
	return "faramesh/" + req.ToolID
}

type awsSecretResponse struct {
	ARN          string `json:"ARN"`
	Name         string `json:"Name"`
	SecretString string `json:"SecretString"`
	VersionID    string `json:"VersionId"`
}
