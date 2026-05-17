package builtin

import (
	"context"
	"time"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

type slowInitServer struct {
	providerv1.UnimplementedProviderServiceServer
	delay time.Duration
}

func newSlowInitServer(delay time.Duration) *slowInitServer {
	if delay <= 0 {
		delay = 2 * time.Second
	}
	return &slowInitServer{delay: delay}
}

func (s *slowInitServer) Init(ctx context.Context, req *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	if !req.GetDryRun() {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_SECRETS},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "slow-init ok"},
		Version:      "test",
	}, nil
}

func (s *slowInitServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true}, nil
}

func (s *slowInitServer) GetSecret(context.Context, *providerv1.SecretRequest) (*providerv1.Secret, error) {
	return nil, unimplemented("SECRETS")
}
