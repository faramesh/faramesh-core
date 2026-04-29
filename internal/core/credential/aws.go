package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// AWSSecretsConfig configures the AWS Secrets Manager broker.
type AWSSecretsConfig struct {
	Region       string
	Endpoint     string // override for testing/localstack
	AccessKey    string // falls back to default credential chain
	SecretKey    string
	SessionToken string
	Timeout      time.Duration
}

func (c *AWSSecretsConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
}

// NewAWSSecretsBroker creates an AWS Secrets Manager broker.
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
	endpoint := strings.TrimRight(b.resolveEndpoint(), "/")
	payload, err := json.Marshal(awsGetSecretValueRequest{SecretID: secretID})
	if err != nil {
		return nil, fmt.Errorf("aws secrets: build request payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("aws secrets: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpReq.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	if err := signAWSSecretsRequest(ctx, httpReq, payload, b.cfg); err != nil {
		return nil, err
	}

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

type awsGetSecretValueRequest struct {
	SecretID string `json:"SecretId"`
}

func signAWSSecretsRequest(ctx context.Context, httpReq *http.Request, payload []byte, cfg AWSSecretsConfig) error {
	creds, err := resolveAWSCredentials(ctx, cfg)
	if err != nil {
		return fmt.Errorf("aws secrets: resolve credentials: %w", err)
	}
	payloadHash := sha256.Sum256(payload)
	signer := v4.NewSigner()
	if err := signer.SignHTTP(
		ctx,
		creds,
		httpReq,
		hex.EncodeToString(payloadHash[:]),
		"secretsmanager",
		cfg.Region,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("aws secrets: sign request: %w", err)
	}
	return nil
}

func resolveAWSCredentials(ctx context.Context, cfg AWSSecretsConfig) (aws.Credentials, error) {
	if cfg.AccessKey != "" || cfg.SecretKey != "" || cfg.SessionToken != "" {
		if cfg.AccessKey == "" || cfg.SecretKey == "" {
			return aws.Credentials{}, fmt.Errorf("access key and secret key must both be set when using explicit AWS credentials")
		}
		staticProvider := credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken)
		return staticProvider.Retrieve(ctx)
	}

	loaded, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return aws.Credentials{}, err
	}
	return loaded.Credentials.Retrieve(ctx)
}
