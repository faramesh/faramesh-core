package core

import (
	"errors"
	"sync"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const dprQueuePolicy = `
faramesh-version: "1.0"
agent-id: "dpr-queue-agent"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

type captureStore struct {
	ch chan *dpr.Record
}

func newCaptureStore() *captureStore {
	return &captureStore{ch: make(chan *dpr.Record, 8)}
}

func (s *captureStore) Save(rec *dpr.Record) error {
	s.ch <- rec
	return nil
}
func (s *captureStore) ByID(string) (*dpr.Record, error)                 { return nil, errors.New("not implemented") }
func (s *captureStore) RecentByAgent(string, int) ([]*dpr.Record, error) { return nil, nil }
func (s *captureStore) Recent(int) ([]*dpr.Record, error)                { return nil, nil }
func (s *captureStore) LastHash(string) (string, error)                  { return "", nil }
func (s *captureStore) KnownAgents() ([]string, error)                   { return nil, nil }
func (s *captureStore) VerifyChain(string) (*dpr.ChainBreak, error)      { return nil, nil }
func (s *captureStore) Close() error                                     { return nil }

type captureQueue struct {
	mu        sync.Mutex
	calls     int
	lastRecID string
	err       error
}

func (q *captureQueue) EnqueueDPR(rec *dpr.Record) error {
	q.mu.Lock()
	q.calls++
	if rec != nil {
		q.lastRecID = rec.RecordID
	}
	err := q.err
	q.mu.Unlock()
	return err
}
func (q *captureQueue) Close() error { return nil }

func buildDPRQueuePipeline(t *testing.T, store dpr.StoreBackend, queue jobs.DPRQueue) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(dprQueuePolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Store:    store,
		DPRQueue: queue,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func dprQueueReq(callID string) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    callID,
		AgentID:   "dpr-queue-agent",
		SessionID: "dpr-queue-sess",
		ToolID:    "safe/read",
		Args:      map[string]any{"x": 1},
		Timestamp: time.Now(),
	}
}

func TestDPRPersistenceUsesQueueWhenConfigured(t *testing.T) {
	store := newCaptureStore()
	queue := &captureQueue{}
	p := buildDPRQueuePipeline(t, store, queue)

	d := p.Evaluate(dprQueueReq("queue-configured"))
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		queue.mu.Lock()
		calls := queue.calls
		queue.mu.Unlock()
		if calls > 0 {
			select {
			case <-store.ch:
				t.Fatalf("store.Save should not be called directly when queue enqueue succeeds")
			default:
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected queue enqueue to be called")
}

func TestDPRPersistenceFallbackDirectAsyncSaveWithoutQueue(t *testing.T) {
	store := newCaptureStore()
	p := buildDPRQueuePipeline(t, store, nil)

	d := p.Evaluate(dprQueueReq("queue-absent"))
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}

	select {
	case <-store.ch:
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("expected async direct store.Save when queue is absent")
	}
}

func TestDPRQueueEnqueueFailureDegradesToDirectAsyncSaveWithoutDecisionChange(t *testing.T) {
	store := newCaptureStore()
	queue := &captureQueue{err: errors.New("enqueue failed")}
	p := buildDPRQueuePipeline(t, store, queue)

	d := p.Evaluate(dprQueueReq("queue-fail"))
	if d.Effect != EffectPermit {
		t.Fatalf("decision should remain permit on enqueue failure, got %s (%s)", d.Effect, d.Reason)
	}

	select {
	case <-store.ch:
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("expected fallback async direct store.Save after enqueue failure")
	}
}
