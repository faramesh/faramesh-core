package builtin

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type devVaultServer struct {
	providerv1.UnimplementedProviderServiceServer
	broker *credential.DevBroker
}

func newDevVaultServer() *devVaultServer {
	return &devVaultServer{broker: &credential.DevBroker{}}
}

func (s *devVaultServer) Init(context.Context, *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_SECRETS},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "dev vault stub"},
		Version:      "builtin-dev",
	}, nil
}

func (s *devVaultServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true, Detail: "ok"}, nil
}

func (s *devVaultServer) GetSecret(ctx context.Context, req *providerv1.SecretRequest) (*providerv1.Secret, error) {
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
	out := &providerv1.Secret{Value: []byte(cred.Value), Version: cred.Source}
	if !cred.ExpiresAt.IsZero() {
		if d := timeUntil(cred.ExpiresAt); d > 0 {
			out.Ttl = durationpb.New(d)
		}
	}
	return out, nil
}

func (s *devVaultServer) VerifyIdentity(context.Context, *providerv1.Identity) (*providerv1.VerificationResult, error) {
	return nil, unimplemented("IDENTITY")
}

func (s *devVaultServer) Sign(context.Context, *providerv1.SignRequest) (*providerv1.Signature, error) {
	return nil, unimplemented("KMS")
}

func (s *devVaultServer) SinkDPR(context.Context, *providerv1.DPRRecord) (*providerv1.SinkAck, error) {
	return nil, unimplemented("AUDIT_SINK")
}

func (s *devVaultServer) CostEstimate(context.Context, *providerv1.CostRequest) (*providerv1.CostEstimateResponse, error) {
	return nil, unimplemented("COST")
}

type devSpiffeServer struct {
	providerv1.UnimplementedProviderServiceServer
	trustDomain string
}

func newDevSpiffeServer() *devSpiffeServer {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	return &devSpiffeServer{trustDomain: fmt.Sprintf("spiffe://dev.local/workload/%s", host)}
}

func (s *devSpiffeServer) Init(context.Context, *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_IDENTITY},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "ephemeral dev SPIFFE CA"},
		Version:      "builtin-dev",
	}, nil
}

func (s *devSpiffeServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true}, nil
}

func (s *devSpiffeServer) VerifyIdentity(_ context.Context, id *providerv1.Identity) (*providerv1.VerificationResult, error) {
	if id == nil || strings.TrimSpace(id.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "identity id required")
	}
	spiffeID := strings.TrimSpace(id.GetId())
	if !strings.HasPrefix(spiffeID, "spiffe://dev.local/") {
		return &providerv1.VerificationResult{Valid: false, Reason: "unknown trust domain"}, nil
	}
	return &providerv1.VerificationResult{Valid: true, Subject: spiffeID, Reason: "dev CA"}, nil
}

func (s *devSpiffeServer) DefaultSPIFFEID() string {
	return s.trustDomain
}

func (s *devSpiffeServer) GetSecret(context.Context, *providerv1.SecretRequest) (*providerv1.Secret, error) {
	return nil, unimplemented("SECRETS")
}

func (s *devSpiffeServer) Sign(context.Context, *providerv1.SignRequest) (*providerv1.Signature, error) {
	return nil, unimplemented("KMS")
}

func (s *devSpiffeServer) SinkDPR(context.Context, *providerv1.DPRRecord) (*providerv1.SinkAck, error) {
	return nil, unimplemented("AUDIT_SINK")
}

func (s *devSpiffeServer) CostEstimate(context.Context, *providerv1.CostRequest) (*providerv1.CostEstimateResponse, error) {
	return nil, unimplemented("COST")
}
