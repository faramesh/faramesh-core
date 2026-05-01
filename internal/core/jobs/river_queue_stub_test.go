package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type fakeRiverClient struct {
	lastArgs  DPRPersistJobArgs
	lastOpts  *river.InsertOpts
	insertErr error
	stopped   bool
}

func (f *fakeRiverClient) Insert(_ context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	typed, ok := args.(DPRPersistJobArgs)
	if !ok {
		return nil, errors.New("unexpected args type")
	}
	f.lastArgs = typed
	f.lastOpts = opts
	if f.insertErr != nil {
		return nil, f.insertErr
	}
	return &rivertype.JobInsertResult{}, nil
}

func (f *fakeRiverClient) Start(context.Context) error { return nil }

func (f *fakeRiverClient) Stop(context.Context) error {
	f.stopped = true
	return nil
}

type fakeRiverPool struct {
	closed bool
}

func (p *fakeRiverPool) Close() { p.closed = true }

type saveCaptureStore struct {
	last *dpr.Record
	err  error
}

func (s *saveCaptureStore) Save(rec *dpr.Record) error                           { s.last = rec; return s.err }
func (s *saveCaptureStore) ByID(string) (*dpr.Record, error)                     { return nil, nil }
func (s *saveCaptureStore) RecentByAgent(string, int) ([]*dpr.Record, error)     { return nil, nil }
func (s *saveCaptureStore) Recent(int) ([]*dpr.Record, error)                    { return nil, nil }
func (s *saveCaptureStore) LastHash(string) (string, error)                      { return "", nil }
func (s *saveCaptureStore) KnownAgents() ([]string, error)                       { return nil, nil }
func (s *saveCaptureStore) VerifyChain(string) (*dpr.ChainBreak, error)          { return nil, nil }
func (s *saveCaptureStore) UpdateSignature(string, string, string, string) error { return nil }
func (s *saveCaptureStore) Close() error                                         { return nil }

type blockingSaveStore struct {
	mu      sync.Mutex
	saved   []string
	started chan struct{}
	release chan struct{}
}

func (s *blockingSaveStore) Save(rec *dpr.Record) error {
	if rec == nil {
		return nil
	}
	s.mu.Lock()
	s.saved = append(s.saved, rec.RecordID)
	first := len(s.saved) == 1
	s.mu.Unlock()
	if first {
		select {
		case s.started <- struct{}{}:
		default:
		}
		<-s.release
	}
	return nil
}
func (s *blockingSaveStore) ByID(string) (*dpr.Record, error) { return nil, nil }
func (s *blockingSaveStore) RecentByAgent(string, int) ([]*dpr.Record, error) {
	return nil, nil
}
func (s *blockingSaveStore) Recent(int) ([]*dpr.Record, error)                    { return nil, nil }
func (s *blockingSaveStore) LastHash(string) (string, error)                      { return "", nil }
func (s *blockingSaveStore) KnownAgents() ([]string, error)                       { return nil, nil }
func (s *blockingSaveStore) VerifyChain(string) (*dpr.ChainBreak, error)          { return nil, nil }
func (s *blockingSaveStore) UpdateSignature(string, string, string, string) error { return nil }
func (s *blockingSaveStore) Close() error                                         { return nil }

func (s *blockingSaveStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.saved)
}

func TestRiverPostgresDSN(t *testing.T) {
	got, err := riverPostgresDSN("river://postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("unexpected postgres dsn: %q", got)
	}
	if _, err := riverPostgresDSN("postgres://localhost/db"); err == nil {
		t.Fatalf("expected invalid dsn error")
	}
}

func TestRiverQueueEnqueueMarshalsRecordAndUsesQueue(t *testing.T) {
	fc := &fakeRiverClient{}
	fp := &fakeRiverPool{}
	q := &RiverDPRQueue{client: fc, pool: fp}

	rec := &dpr.Record{
		RecordID:  "rec-1",
		AgentID:   "agent",
		ToolID:    "tool",
		CreatedAt: time.Now(),
	}
	if err := q.EnqueueDPR(rec); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}
	if fc.lastOpts == nil || fc.lastOpts.Queue != dprPersistQueueName {
		t.Fatalf("expected queue %q, got %+v", dprPersistQueueName, fc.lastOpts)
	}
	var decoded dpr.Record
	if err := json.Unmarshal(fc.lastArgs.RecordJSON, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decoded.RecordID != rec.RecordID || decoded.AgentID != rec.AgentID || decoded.ToolID != rec.ToolID {
		t.Fatalf("decoded payload mismatch: %#v", decoded)
	}
}

func TestRiverQueueEnqueueError(t *testing.T) {
	q := &RiverDPRQueue{client: &fakeRiverClient{insertErr: errors.New("boom")}}
	if err := q.EnqueueDPR(&dpr.Record{RecordID: "x"}); err == nil {
		t.Fatalf("expected enqueue error")
	}
}

func TestRiverQueueCloseStopsClientAndPool(t *testing.T) {
	fc := &fakeRiverClient{}
	fp := &fakeRiverPool{}
	q := &RiverDPRQueue{client: fc, pool: fp}
	if err := q.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if !fc.stopped {
		t.Fatalf("expected client stop")
	}
	if !fp.closed {
		t.Fatalf("expected pool close")
	}
}

func TestDPRPersistWorkerCallsStoreSave(t *testing.T) {
	store := &saveCaptureStore{}
	worker := &dprPersistWorker{store: store}
	rec := dpr.Record{RecordID: "rec-1", AgentID: "agent-1", ToolID: "tool-1", CreatedAt: time.Now()}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	job := &river.Job[DPRPersistJobArgs]{Args: DPRPersistJobArgs{RecordJSON: payload}}
	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatalf("worker failed: %v", err)
	}
	if store.last == nil || store.last.RecordID != rec.RecordID {
		t.Fatalf("expected store save call with record")
	}
}

func TestInprocDPRQueueCloseDrainsQueuedRecords(t *testing.T) {
	store := &blockingSaveStore{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	q := NewInprocDPRQueue(store, InprocDPRQueueConfig{Buffer: 2})

	if err := q.EnqueueDPR(&dpr.Record{RecordID: "rec-1"}); err != nil {
		t.Fatalf("enqueue rec-1: %v", err)
	}
	if err := q.EnqueueDPR(&dpr.Record{RecordID: "rec-2"}); err != nil {
		t.Fatalf("enqueue rec-2: %v", err)
	}

	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for first save to start")
	}

	closed := make(chan struct{})
	go func() {
		_ = q.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatalf("queue close returned before blocked save released")
	case <-time.After(100 * time.Millisecond):
	}

	close(store.release)

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatalf("queue close did not finish after releasing blocked save")
	}

	if got := store.count(); got != 2 {
		t.Fatalf("expected 2 saved records after drain, got %d", got)
	}
}

func TestInprocDPRQueueEnqueueAfterClose(t *testing.T) {
	q := NewInprocDPRQueue(&saveCaptureStore{}, InprocDPRQueueConfig{Buffer: 1})
	if err := q.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if err := q.EnqueueDPR(&dpr.Record{RecordID: "rec-1"}); err == nil {
		t.Fatalf("expected enqueue-after-close error")
	}
}
