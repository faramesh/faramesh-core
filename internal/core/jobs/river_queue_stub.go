package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

const dprPersistQueueName = "dpr_persist"

// DPRPersistJobArgs is the durable payload persisted into River.
type DPRPersistJobArgs struct {
	RecordJSON json.RawMessage `json:"record_json"`
}

// Kind identifies the River job kind.
func (DPRPersistJobArgs) Kind() string { return "dpr.persist" }

// RiverDPRQueue is a DPR queue backed by River + PostgreSQL.
type RiverDPRQueue struct {
	client riverClient
	pool   riverPool
	once   sync.Once
}

type riverClient interface {
	Insert(context.Context, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
	Start(context.Context) error
	Stop(context.Context) error
}

type riverPool interface {
	Close()
}

// NewRiverDPRQueue creates a River-backed DPR queue and starts worker loops.
// dsn must be "river://<postgres-dsn>".
func NewRiverDPRQueue(dsn string, store dpr.StoreBackend) (DPRQueue, error) {
	if store == nil {
		return nil, fmt.Errorf("nil DPR store for river queue")
	}
	pgDSN, err := riverPostgresDSN(dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		return nil, fmt.Errorf("open river postgres pool: %w", err)
	}

	workers := river.NewWorkers()
	river.AddWorker(workers, &dprPersistWorker{store: store})

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Workers: workers,
		Queues: map[string]river.QueueConfig{
			dprPersistQueueName: {MaxWorkers: 4},
		},
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("create river client: %w", err)
	}
	if err := client.Start(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("start river client: %w", err)
	}

	return &RiverDPRQueue{client: client, pool: pool}, nil
}

// EnqueueDPR inserts an async DPR persist job into River.
func (q *RiverDPRQueue) EnqueueDPR(rec *dpr.Record) error {
	if rec == nil {
		return fmt.Errorf("nil DPR record")
	}
	if q == nil || q.client == nil {
		return fmt.Errorf("river DPR queue not initialized")
	}
	recordJSON, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal DPR record for queue: %w", err)
	}
	_, err = q.client.Insert(context.Background(), DPRPersistJobArgs{RecordJSON: recordJSON}, &river.InsertOpts{
		Queue: dprPersistQueueName,
	})
	if err != nil {
		observe.Default.RecordDPREnqueue(false)
		return fmt.Errorf("insert DPR persist job: %w", err)
	}
	observe.Default.RecordDPREnqueue(true)
	return nil
}

// Close stops River workers and closes the DB pool.
func (q *RiverDPRQueue) Close() error {
	if q == nil {
		return nil
	}
	var stopErr error
	q.once.Do(func() {
		if q.client != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stopErr = q.client.Stop(ctx)
		}
		if q.pool != nil {
			q.pool.Close()
		}
	})
	if stopErr != nil {
		return fmt.Errorf("stop river client: %w", stopErr)
	}
	return nil
}

func riverPostgresDSN(dsn string) (string, error) {
	if !SupportsRiverDSN(dsn) {
		return "", fmt.Errorf("river queue requires river:// DSN")
	}
	pgDSN := strings.TrimPrefix(dsn, "river://")
	if strings.TrimSpace(pgDSN) == "" {
		return "", fmt.Errorf("river queue DSN missing postgres target")
	}
	return pgDSN, nil
}

type dprPersistWorker struct {
	river.WorkerDefaults[DPRPersistJobArgs]
	store dpr.StoreBackend
}

func (w *dprPersistWorker) Work(ctx context.Context, job *river.Job[DPRPersistJobArgs]) error {
	if w == nil || w.store == nil {
		return fmt.Errorf("nil DPR store in worker")
	}
	var rec dpr.Record
	if err := json.Unmarshal(job.Args.RecordJSON, &rec); err != nil {
		observe.Default.RecordDPRAsyncPersist(false)
		return fmt.Errorf("decode DPR record payload: %w", err)
	}
	err := w.store.Save(&rec)
	observe.Default.RecordDPRAsyncPersist(err == nil)
	return err
}
