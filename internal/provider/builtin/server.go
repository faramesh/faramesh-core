package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func unimplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "%s capability not supported by this provider", method)
}

func healthy(detail string) *providerv1.ProviderInfo {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_SECRETS},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: detail},
		Version:      "builtin",
	}
}

func dryRunSecrets(cfg map[string]string, required ...string) (*providerv1.ProviderInfo, error) {
	for _, k := range required {
		if strings.TrimSpace(cfg[k]) == "" {
			return nil, fmt.Errorf("missing required config %q", k)
		}
	}
	return healthy("dry-run ok"), nil
}

// secretsServer wraps a credential.Broker as ProviderService SECRETS capability.
type secretsServer struct {
	providerv1.UnimplementedProviderServiceServer
	broker      credential.Broker
	required    []string
	displayType string
}

func (s *secretsServer) Init(ctx context.Context, req *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	cfg := req.GetConfig()
	if req.GetDryRun() {
		return dryRunSecrets(cfg, s.required...)
	}
	_ = ctx
	return healthy("initialized"), nil
}

func (s *secretsServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true, Detail: "ok"}, nil
}

func (s *secretsServer) GetSecret(ctx context.Context, req *providerv1.SecretRequest) (*providerv1.Secret, error) {
	path := strings.TrimSpace(req.GetPath())
	if path == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}
	cred, err := s.broker.Fetch(ctx, credential.FetchRequest{
		ToolID: "faramesh/credential",
		Scope:  path,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get secret: %v", err)
	}
	out := &providerv1.Secret{
		Value:   []byte(cred.Value),
		Version: cred.Source,
	}
	if !cred.ExpiresAt.IsZero() {
		if d := timeUntil(cred.ExpiresAt); d > 0 {
			out.Ttl = durationpb.New(d)
		}
	}
	return out, nil
}

func (s *secretsServer) VerifyIdentity(context.Context, *providerv1.Identity) (*providerv1.VerificationResult, error) {
	return nil, unimplemented("IDENTITY")
}

func (s *secretsServer) Sign(context.Context, *providerv1.SignRequest) (*providerv1.Signature, error) {
	return nil, unimplemented("KMS")
}

func (s *secretsServer) SinkDPR(context.Context, *providerv1.DPRRecord) (*providerv1.SinkAck, error) {
	return nil, unimplemented("AUDIT_SINK")
}

func (s *secretsServer) CostEstimate(context.Context, *providerv1.CostRequest) (*providerv1.CostEstimateResponse, error) {
	return nil, unimplemented("COST")
}

func timeUntil(t time.Time) time.Duration {
	d := time.Until(t)
	if d < 0 {
		return 0
	}
	return d
}
