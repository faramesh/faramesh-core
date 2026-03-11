// Package backends defines non-blocking DEFER backends for durable task queuing.
//
// The default in-memory DEFER workflow (workflow.go) is fine for single-process
// deployments, but production systems need durable, distributed backends:
//
//   - Temporal: Full workflow orchestration with retries, timers, visibility
//   - Redis: Simple queue + pub/sub for lightweight deployments
//   - SQS: AWS-native queue for serverless environments
//   - Polling: SDK-side polling interface for custom integrations
package backends

import (
	"context"
	"time"
)

// DeferItem represents a deferred call waiting for approval.
type DeferItem struct {
	Token       string            `json:"token"`
	AgentID     string            `json:"agent_id"`
	ToolID      string            `json:"tool_id"`
	Reason      string            `json:"reason"`
	Args        map[string]any    `json:"args,omitempty"`
	Priority    string            `json:"priority"` // critical, high, normal
	CreatedAt   time.Time         `json:"created_at"`
	Deadline    time.Time         `json:"deadline"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// DeferResolution is the outcome of a resolved DEFER from a backend.
type DeferResolution struct {
	Token       string         `json:"token"`
	Approved    bool           `json:"approved"`
	Reason      string         `json:"reason"`
	ModifiedArgs map[string]any `json:"modified_args,omitempty"` // for conditional approval
	ResolvedBy  string         `json:"resolved_by,omitempty"`
	ResolvedAt  time.Time      `json:"resolved_at"`
}

// Backend is the interface for durable DEFER queue backends.
type Backend interface {
	// Enqueue adds a deferred item to the queue.
	Enqueue(ctx context.Context, item DeferItem) error

	// WaitForResolution blocks until the item is resolved or the context is cancelled.
	WaitForResolution(ctx context.Context, token string) (*DeferResolution, error)

	// Resolve approves or denies a deferred item.
	Resolve(ctx context.Context, resolution DeferResolution) error

	// Pending returns all pending deferred items.
	Pending(ctx context.Context) ([]DeferItem, error)

	// Close shuts down the backend.
	Close() error
}

// RedisBackend uses Redis lists + pub/sub for DEFER queue.
type RedisBackend struct {
	addr    string
	prefix  string
}

// NewRedisBackend creates a Redis-based DEFER backend.
func NewRedisBackend(addr, prefix string) *RedisBackend {
	if prefix == "" {
		prefix = "faramesh:defer"
	}
	return &RedisBackend{addr: addr, prefix: prefix}
}

func (rb *RedisBackend) Enqueue(_ context.Context, _ DeferItem) error {
	// In production: RPUSH {prefix}:queue {json}
	// SETEX {prefix}:item:{token} {ttl} {json}
	// PUBLISH {prefix}:new {token}
	return nil
}

func (rb *RedisBackend) WaitForResolution(ctx context.Context, token string) (*DeferResolution, error) {
	// In production: SUBSCRIBE {prefix}:resolved:{token}
	// Block until message received or context cancelled.
	<-ctx.Done()
	return nil, ctx.Err()
}

func (rb *RedisBackend) Resolve(_ context.Context, _ DeferResolution) error {
	// In production: SET {prefix}:resolved:{token} {json}
	// PUBLISH {prefix}:resolved:{token} {json}
	// LREM {prefix}:queue 1 {json}
	return nil
}

func (rb *RedisBackend) Pending(_ context.Context) ([]DeferItem, error) {
	// In production: LRANGE {prefix}:queue 0 -1
	return nil, nil
}

func (rb *RedisBackend) Close() error { return nil }

// SQSBackend uses AWS SQS for DEFER queue in serverless environments.
type SQSBackend struct {
	queueURL string
	region   string
}

// NewSQSBackend creates an SQS-based DEFER backend.
func NewSQSBackend(queueURL, region string) *SQSBackend {
	return &SQSBackend{queueURL: queueURL, region: region}
}

func (sb *SQSBackend) Enqueue(_ context.Context, _ DeferItem) error {
	// In production: sqs.SendMessage with MessageBody = JSON(item)
	// MessageGroupId = item.Priority for FIFO queues
	return nil
}

func (sb *SQSBackend) WaitForResolution(ctx context.Context, _ string) (*DeferResolution, error) {
	// In production: Long-poll SQS with ReceiveMessage
	<-ctx.Done()
	return nil, ctx.Err()
}

func (sb *SQSBackend) Resolve(_ context.Context, _ DeferResolution) error {
	// In production: Write resolution to DynamoDB or response SQS queue
	return nil
}

func (sb *SQSBackend) Pending(_ context.Context) ([]DeferItem, error) {
	return nil, nil
}

func (sb *SQSBackend) Close() error { return nil }

// PollingBackend provides an SDK-side polling interface for custom integrations.
// Instead of push notifications, the SDK polls for pending/resolved items.
type PollingBackend struct {
	items    map[string]*DeferItem
	resolved map[string]*DeferResolution
}

// NewPollingBackend creates a polling-based DEFER backend.
func NewPollingBackend() *PollingBackend {
	return &PollingBackend{
		items:    make(map[string]*DeferItem),
		resolved: make(map[string]*DeferResolution),
	}
}

func (pb *PollingBackend) Enqueue(_ context.Context, item DeferItem) error {
	pb.items[item.Token] = &item
	return nil
}

func (pb *PollingBackend) WaitForResolution(ctx context.Context, token string) (*DeferResolution, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if r, ok := pb.resolved[token]; ok {
				return r, nil
			}
		}
	}
}

func (pb *PollingBackend) Resolve(_ context.Context, resolution DeferResolution) error {
	pb.resolved[resolution.Token] = &resolution
	delete(pb.items, resolution.Token)
	return nil
}

func (pb *PollingBackend) Pending(_ context.Context) ([]DeferItem, error) {
	items := make([]DeferItem, 0, len(pb.items))
	for _, item := range pb.items {
		items = append(items, *item)
	}
	return items, nil
}

func (pb *PollingBackend) Close() error { return nil }
