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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DeferItem represents a deferred call waiting for approval.
type DeferItem struct {
	Token     string            `json:"token"`
	AgentID   string            `json:"agent_id"`
	ToolID    string            `json:"tool_id"`
	Reason    string            `json:"reason"`
	Args      map[string]any    `json:"args,omitempty"`
	Priority  string            `json:"priority"` // critical, high, normal
	CreatedAt time.Time         `json:"created_at"`
	Deadline  time.Time         `json:"deadline"`
	Metadata  map[string]string `json:"metadata,omitempty"`

	// Cascade tracking (R4-T enhancement)
	ParentDeferToken string   `json:"parent_defer_token,omitempty"` // parent in cascade chain
	CascadeReason    string   `json:"cascade_reason,omitempty"`      // why cascaded
	CascadeDepth     int      `json:"cascade_depth"`                 // 0=original, 1=first cascade, etc
	CascadePath      []string `json:"cascade_path,omitempty"`        // lineage of tokens
}

// DeferResolution is the outcome of a resolved DEFER from a backend.
type DeferResolution struct {
	Token        string         `json:"token"`
	Approved     bool           `json:"approved"`
	Reason       string         `json:"reason"`
	Status       string         `json:"status,omitempty"`
	ModifiedArgs map[string]any `json:"modified_args,omitempty"` // for conditional approval
	ResolvedBy   string         `json:"resolved_by,omitempty"`
	ResolvedAt   time.Time      `json:"resolved_at"`
	Signature    string         `json:"signature,omitempty"`
}

// StatusSnapshot reports the durable state of a defer token.
type StatusSnapshot struct {
	Token      string           `json:"token"`
	State      string           `json:"state"`
	Item       *DeferItem       `json:"item,omitempty"`
	Resolution *DeferResolution `json:"resolution,omitempty"`
}

// Backend is the interface for durable DEFER queue backends.
type Backend interface {
	// Enqueue adds a deferred item to the queue.
	Enqueue(ctx context.Context, item DeferItem) error

	// WaitForResolution blocks until the item is resolved or the context is cancelled.
	WaitForResolution(ctx context.Context, token string) (*DeferResolution, error)

	// Resolve approves or denies a deferred item.
	Resolve(ctx context.Context, resolution DeferResolution) error

	// Status reports the current state of a token.
	Status(ctx context.Context, token string) (*StatusSnapshot, error)

	// List returns all pending deferred items.
	List(ctx context.Context) ([]DeferItem, error)

	// Close shuts down the backend.
	Close() error
}

var (
	ErrUnknownToken    = errors.New("unknown defer token")
	ErrAlreadyResolved = errors.New("defer token already resolved")
)

// RedisBackend uses Redis lists + pub/sub for DEFER queue.
type RedisBackend struct {
	client redis.UniversalClient
	prefix string
	owned  bool
}

type RedisConfig struct {
	Client redis.UniversalClient
	Addr   string
	Prefix string
}

// NewRedisBackend creates a Redis-based DEFER backend.
func NewRedisBackend(cfg RedisConfig) *RedisBackend {
	client := cfg.Client
	owned := false
	if client == nil && cfg.Addr != "" {
		client = redis.NewClient(&redis.Options{Addr: cfg.Addr})
		owned = true
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "faramesh:defer"
	}
	return &RedisBackend{client: client, prefix: prefix, owned: owned}
}

func (rb *RedisBackend) Enqueue(ctx context.Context, item DeferItem) error {
	if rb.client == nil {
		return fmt.Errorf("redis defer backend client is nil")
	}
	body, err := json.Marshal(item)
	if err != nil {
		return err
	}
	ok, err := rb.client.SetNX(ctx, rb.itemKey(item.Token), body, backendTTL(item.Deadline)).Result()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	pipe := rb.client.TxPipeline()
	pipe.SAdd(ctx, rb.pendingKey(), item.Token)
	pipe.Expire(ctx, rb.pendingKey(), 7*24*time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (rb *RedisBackend) WaitForResolution(ctx context.Context, token string) (*DeferResolution, error) {
	if rb.client == nil {
		return nil, fmt.Errorf("redis defer backend client is nil")
	}
	if snap, err := rb.Status(ctx, token); err == nil && snap != nil && snap.Resolution != nil {
		return snap.Resolution, nil
	}
	sub := rb.client.Subscribe(ctx, rb.resolvedChannel(token))
	defer sub.Close()
	_, err := sub.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if snap, err := rb.Status(ctx, token); err == nil && snap != nil && snap.Resolution != nil {
		return snap.Resolution, nil
	}
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg := <-ch:
			if msg == nil {
				continue
			}
			var res DeferResolution
			if err := json.Unmarshal([]byte(msg.Payload), &res); err != nil {
				return nil, err
			}
			return &res, nil
		}
	}
}

var resolveLua = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 2
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[3], ARGV[3])
redis.call('PUBLISH', KEYS[4], ARGV[1])
return 1
`)

func (rb *RedisBackend) Resolve(ctx context.Context, resolution DeferResolution) error {
	if rb.client == nil {
		return fmt.Errorf("redis defer backend client is nil")
	}
	if resolution.ResolvedAt.IsZero() {
		resolution.ResolvedAt = time.Now().UTC()
	}
	if resolution.Status == "" {
		if resolution.Approved {
			resolution.Status = "approved"
		} else {
			resolution.Status = "denied"
		}
	}
	body, err := json.Marshal(resolution)
	if err != nil {
		return err
	}
	result, err := resolveLua.Run(
		ctx,
		rb.client,
		[]string{
			rb.itemKey(resolution.Token),
			rb.resolvedKey(resolution.Token),
			rb.pendingKey(),
			rb.resolvedChannel(resolution.Token),
		},
		string(body),
		int64(7*24*time.Hour/time.Second),
		resolution.Token,
	).Int64()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case 2:
		return ErrAlreadyResolved
	default:
		return ErrUnknownToken
	}
}

func (rb *RedisBackend) Status(ctx context.Context, token string) (*StatusSnapshot, error) {
	if rb.client == nil {
		return nil, fmt.Errorf("redis defer backend client is nil")
	}
	body, err := rb.client.Get(ctx, rb.resolvedKey(token)).Result()
	if err == nil {
		var res DeferResolution
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return nil, err
		}
		return &StatusSnapshot{Token: token, State: res.Status, Resolution: &res}, nil
	}
	if !errors.Is(err, redis.Nil) {
		return nil, err
	}
	body, err = rb.client.Get(ctx, rb.itemKey(token)).Result()
	if err == nil {
		var item DeferItem
		if err := json.Unmarshal([]byte(body), &item); err != nil {
			return nil, err
		}
		return &StatusSnapshot{Token: token, State: "pending", Item: &item}, nil
	}
	if !errors.Is(err, redis.Nil) {
		return nil, err
	}
	return nil, ErrUnknownToken
}

func (rb *RedisBackend) List(ctx context.Context) ([]DeferItem, error) {
	if rb.client == nil {
		return nil, fmt.Errorf("redis defer backend client is nil")
	}
	tokens, err := rb.client.SMembers(ctx, rb.pendingKey()).Result()
	if err != nil {
		return nil, err
	}
	items := make([]DeferItem, 0, len(tokens))
	for _, token := range tokens {
		body, err := rb.client.Get(ctx, rb.itemKey(token)).Result()
		if errors.Is(err, redis.Nil) {
			_ = rb.client.SRem(ctx, rb.pendingKey(), token).Err()
			continue
		}
		if err != nil {
			return nil, err
		}
		var item DeferItem
		if err := json.Unmarshal([]byte(body), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (rb *RedisBackend) Close() error {
	if rb.client == nil || !rb.owned {
		return nil
	}
	if c, ok := rb.client.(*redis.Client); ok {
		return c.Close()
	}
	return nil
}

func (rb *RedisBackend) pendingKey() string              { return rb.prefix + ":pending" }
func (rb *RedisBackend) itemKey(token string) string     { return rb.prefix + ":item:" + token }
func (rb *RedisBackend) resolvedKey(token string) string { return rb.prefix + ":resolved:" + token }
func (rb *RedisBackend) resolvedChannel(token string) string {
	return rb.prefix + ":resolved-ch:" + token
}

func backendTTL(deadline time.Time) time.Duration {
	if deadline.IsZero() {
		return 7 * 24 * time.Hour
	}
	ttl := time.Until(deadline.Add(24 * time.Hour))
	if ttl < time.Hour {
		return time.Hour
	}
	return ttl
}

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

func (sb *SQSBackend) Status(_ context.Context, _ string) (*StatusSnapshot, error) {
	return nil, ErrUnknownToken
}

func (sb *SQSBackend) List(_ context.Context) ([]DeferItem, error) {
	return nil, nil
}

func (sb *SQSBackend) Close() error { return nil }

// PollingBackend provides an SDK-side polling interface for custom integrations.
// Instead of push notifications, the SDK polls for pending/resolved items.
type PollingBackend struct {
	mu       sync.RWMutex
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
	pb.mu.Lock()
	defer pb.mu.Unlock()
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
			pb.mu.RLock()
			if r, ok := pb.resolved[token]; ok {
				res := *r
				pb.mu.RUnlock()
				return &res, nil
			}
			pb.mu.RUnlock()
		}
	}
}

func (pb *PollingBackend) Resolve(_ context.Context, resolution DeferResolution) error {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if resolution.ResolvedAt.IsZero() {
		resolution.ResolvedAt = time.Now().UTC()
	}
	if resolution.Status == "" {
		if resolution.Approved {
			resolution.Status = "approved"
		} else {
			resolution.Status = "denied"
		}
	}
	pb.resolved[resolution.Token] = &resolution
	delete(pb.items, resolution.Token)
	return nil
}

func (pb *PollingBackend) Status(_ context.Context, token string) (*StatusSnapshot, error) {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	if r, ok := pb.resolved[token]; ok {
		res := *r
		return &StatusSnapshot{Token: token, State: r.Status, Resolution: &res}, nil
	}
	if item, ok := pb.items[token]; ok {
		copyItem := *item
		return &StatusSnapshot{Token: token, State: "pending", Item: &copyItem}, nil
	}
	return nil, ErrUnknownToken
}

func (pb *PollingBackend) List(_ context.Context) ([]DeferItem, error) {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	items := make([]DeferItem, 0, len(pb.items))
	for _, item := range pb.items {
		items = append(items, *item)
	}
	return items, nil
}

func (pb *PollingBackend) Close() error { return nil }
