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
	store  dpr.StoreBackend
	ch     chan *dpr.Record
	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewInprocDPRQueue creates an in-process DPR queue.
func NewInprocDPRQueue(store dpr.StoreBackend, cfg InprocDPRQueueConfig) *InprocDPRQueue {
	if cfg.Buffer <= 0 {
		cfg.Buffer = 128
	}
	q := &InprocDPRQueue{
		store:  store,
		ch:     make(chan *dpr.Record, cfg.Buffer),
		stopCh: make(chan struct{}),
	}
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for {
			select {
			case rec, ok := <-q.ch:
				if !ok {
					return
				}
				if rec != nil && q.store != nil {
					_ = q.store.Save(rec)
				}
			case <-q.stopCh:
				return
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
	select {
	case q.ch <- rec:
		observe.Default.RecordDPREnqueue(true)
		return nil
	default:
		observe.Default.RecordDPREnqueue(false)
		return fmt.Errorf("inproc DPR queue full")
	}
}

// Close stops the worker and drains no further records.
func (q *InprocDPRQueue) Close() error {
	close(q.stopCh)
	close(q.ch)
	q.wg.Wait()
	return nil
}

// SupportsRiverDSN reports whether DSN explicitly requests River mode.
func SupportsRiverDSN(dsn string) bool {
	return len(dsn) >= 8 && dsn[:8] == "river://"
}
