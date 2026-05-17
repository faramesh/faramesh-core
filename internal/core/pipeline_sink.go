package core

import (
	"context"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// AuditSinkClient forwards DPR records to AUDIT_SINK providers.
type AuditSinkClient interface {
	SinkDPR(ctx context.Context, in *providerv1.DPRRecord, opts ...grpc.CallOption) (*providerv1.SinkAck, error)
}

// CostEstimatorClient estimates tool cost before policy evaluation.
type CostEstimatorClient interface {
	CostEstimate(ctx context.Context, in *providerv1.CostRequest, opts ...grpc.CallOption) (*providerv1.CostEstimateResponse, error)
}

// SetAuditSinks configures post-WAL replication to external audit providers.
func (p *Pipeline) SetAuditSinks(sinks []AuditSinkClient) {
	p.auditSinks = sinks
}

// SetCostEstimator configures optional cost estimation from COST-capable providers.
func (p *Pipeline) SetCostEstimator(c CostEstimatorClient) {
	p.costEstimator = c
}

func (p *Pipeline) replicateToAuditSinks(rec *dpr.Record) {
	if p == nil || rec == nil || len(p.auditSinks) == 0 {
		return
	}
	pb := recordToProviderDPR(rec)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var sinkErr error
	for _, sink := range p.auditSinks {
		if sink == nil {
			continue
		}
		if _, err := sink.SinkDPR(ctx, pb); err != nil && sinkErr == nil {
			sinkErr = err
		}
	}
	if sinkErr != nil && p.log != nil {
		p.log.Warn("audit sink SinkDPR failed", zap.String("record_id", rec.RecordID), zap.Error(sinkErr))
	}
}

func recordToProviderDPR(rec *dpr.Record) *providerv1.DPRRecord {
	if rec == nil {
		return nil
	}
	return &providerv1.DPRRecord{
		RecordId: rec.RecordID,
		AgentId:  rec.AgentID,
	}
}
