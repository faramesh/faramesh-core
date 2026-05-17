package builtin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type auditSinkServer struct {
	providerv1.UnimplementedProviderServiceServer
}

func newAuditSinkServer() *auditSinkServer {
	return &auditSinkServer{}
}

func (s *auditSinkServer) Init(context.Context, *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_AUDIT_SINK},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "audit sink ready"},
		Version:      "builtin",
	}, nil
}

func (s *auditSinkServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true}, nil
}

func (s *auditSinkServer) SinkDPR(_ context.Context, rec *providerv1.DPRRecord) (*providerv1.SinkAck, error) {
	if rec != nil {
		b, _ := json.Marshal(map[string]string{
			"record_id": rec.GetRecordId(),
			"agent_id":  rec.GetAgentId(),
		})
		fmt.Fprintf(os.Stderr, "[audit-sink] %s\n", b)
	}
	return &providerv1.SinkAck{Accepted: true}, nil
}

func (s *auditSinkServer) GetSecret(context.Context, *providerv1.SecretRequest) (*providerv1.Secret, error) {
	return nil, unimplemented("SECRETS")
}

type costServer struct {
	providerv1.UnimplementedProviderServiceServer
}

func newCostServer() *costServer {
	return &costServer{}
}

func (s *costServer) Init(context.Context, *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_COST},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "cost estimator ready"},
		Version:      "builtin",
	}, nil
}

func (s *costServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true}, nil
}

func (s *costServer) CostEstimate(_ context.Context, req *providerv1.CostRequest) (*providerv1.CostEstimateResponse, error) {
	amount := 0.001
	if req != nil && req.GetActionType() != "" {
		amount = 0.01
	}
	return &providerv1.CostEstimateResponse{
		Amount:     amount,
		Currency:   "USD",
		Confidence: 0.5,
	}, nil
}

func (s *costServer) GetSecret(context.Context, *providerv1.SecretRequest) (*providerv1.Secret, error) {
	return nil, unimplemented("SECRETS")
}

type kmsServer struct {
	providerv1.UnimplementedProviderServiceServer
	mu  sync.Mutex
	key *rsa.PrivateKey
}

func newKMSServer() (*kmsServer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &kmsServer{key: key}, nil
}

func (s *kmsServer) Init(context.Context, *providerv1.InitRequest) (*providerv1.ProviderInfo, error) {
	return &providerv1.ProviderInfo{
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_KMS},
		Health:       &providerv1.HealthStatus{Healthy: true, Detail: "ephemeral dev KMS"},
		Version:      "builtin-dev",
	}, nil
}

func (s *kmsServer) HealthCheck(context.Context, *providerv1.HealthRequest) (*providerv1.HealthStatus, error) {
	return &providerv1.HealthStatus{Healthy: true}, nil
}

func (s *kmsServer) Sign(_ context.Context, req *providerv1.SignRequest) (*providerv1.Signature, error) {
	if req == nil || len(req.GetPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "payload required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256(req.GetPayload())
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, 0, sum[:])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	_ = pubDER
	return &providerv1.Signature{
		Algorithm: "RSA-PKCS1v15-SHA256",
		Signature: sig,
		KeyId:     "dev-kms",
	}, nil
}

func (s *kmsServer) GetSecret(context.Context, *providerv1.SecretRequest) (*providerv1.Secret, error) {
	return nil, unimplemented("SECRETS")
}
