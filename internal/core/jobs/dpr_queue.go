package jobs

import (
	"fmt"
	"sync"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
)

// DPRQueue is the minimal enqueue surface for async DPR persistence.
type DPRQueue interface {
	EnqueueDPR(rec *dpr.Record) error
	Close() error
}

// InprocDPRQueueConfig controls the in-process queue.
type InprocDPRQueueConfig struct {
	Buffer int
}

// InprocDPRQueue is a lightweight queue backed by a single worker goroutine.
type InprocDPRQueue struct {
	store     dpr.StoreBackend
	ch        chan *dpr.Record
	wg        sync.WaitGroup
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
}

// NewInprocDPRQueue creates an in-process DPR queue.
func NewInprocDPRQueue(store dpr.StoreBackend, cfg InprocDPRQueueConfig) *InprocDPRQueue {
	if cfg.Buffer <= 0 {
		cfg.Buffer = 128
	}
	q := &InprocDPRQueue{
		store: store,
		ch:    make(chan *dpr.Record, cfg.Buffer),
	}
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for rec := range q.ch {
			if rec != nil && q.store != nil {
				_ = q.store.Save(rec)
			}
		}
	}()
	return q
}

// EnqueueDPR adds a record to the in-process queue.
func (q *InprocDPRQueue) EnqueueDPR(rec *dpr.Record) error {
	if rec == nil {
		return fmt.Errorf("nil DPR record")
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return fmt.Errorf("inproc DPR queue closed")
	}
	select {
	case q.ch <- rec:
		observe.Default.RecordDPREnqueue(true)
		return nil
	default:
		observe.Default.RecordDPREnqueue(false)
		return fmt.Errorf("inproc DPR queue full")
	}
}

// Close stops the worker after draining queued records.
func (q *InprocDPRQueue) Close() error {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.closed = true
		close(q.ch)
		q.mu.Unlock()
	})
	q.wg.Wait()
	return nil
}

// SupportsRiverDSN reports whether DSN explicitly requests River mode.
func SupportsRiverDSN(dsn string) bool {
	return len(dsn) >= 8 && dsn[:8] == "river://"
}
