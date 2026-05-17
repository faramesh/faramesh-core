package provider

import (
	"context"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"google.golang.org/grpc"
)

// localClient implements ProviderServiceClient against an in-process server.
type localClient struct {
	srv providerv1.ProviderServiceServer
}

func newLocalClient(srv providerv1.ProviderServiceServer) providerv1.ProviderServiceClient {
	return &localClient{srv: srv}
}

func (c *localClient) Init(ctx context.Context, in *providerv1.InitRequest, _ ...grpc.CallOption) (*providerv1.ProviderInfo, error) {
	return c.srv.Init(ctx, in)
}

func (c *localClient) HealthCheck(ctx context.Context, in *providerv1.HealthRequest, _ ...grpc.CallOption) (*providerv1.HealthStatus, error) {
	return c.srv.HealthCheck(ctx, in)
}

func (c *localClient) GetSecret(ctx context.Context, in *providerv1.SecretRequest, _ ...grpc.CallOption) (*providerv1.Secret, error) {
	return c.srv.GetSecret(ctx, in)
}

func (c *localClient) VerifyIdentity(ctx context.Context, in *providerv1.Identity, _ ...grpc.CallOption) (*providerv1.VerificationResult, error) {
	return c.srv.VerifyIdentity(ctx, in)
}

func (c *localClient) Sign(ctx context.Context, in *providerv1.SignRequest, _ ...grpc.CallOption) (*providerv1.Signature, error) {
	return c.srv.Sign(ctx, in)
}

func (c *localClient) SinkDPR(ctx context.Context, in *providerv1.DPRRecord, _ ...grpc.CallOption) (*providerv1.SinkAck, error) {
	return c.srv.SinkDPR(ctx, in)
}

func (c *localClient) CostEstimate(ctx context.Context, in *providerv1.CostRequest, _ ...grpc.CallOption) (*providerv1.CostEstimateResponse, error) {
	return c.srv.CostEstimate(ctx, in)
}
