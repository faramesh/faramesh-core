package backends

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisBackendLifecycle(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	backend := NewRedisBackend(RedisConfig{Client: client, Prefix: "test:defer"})
	t.Cleanup(func() { _ = backend.Close() })

	item := DeferItem{
		Token:     "tok-1",
		AgentID:   "agent-a",
		ToolID:    "tool-x",
		Reason:    "needs review",
		Priority:  "high",
		CreatedAt: time.Now().UTC(),
		Deadline:  time.Now().UTC().Add(5 * time.Minute),
	}
	if err := backend.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	list, err := backend.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Token != item.Token {
		t.Fatalf("unexpected list: %#v", list)
	}

	snap, err := backend.Status(context.Background(), item.Token)
	if err != nil {
		t.Fatalf("status pending: %v", err)
	}
	if snap.State != "pending" || snap.Item == nil || snap.Item.Token != item.Token {
		t.Fatalf("unexpected pending snapshot: %#v", snap)
	}

	res := DeferResolution{
		Token:      item.Token,
		Approved:   true,
		Status:     "approved",
		Reason:     "ok",
		ResolvedBy: "approver-1",
		ResolvedAt: time.Now().UTC(),
	}
	if err := backend.Resolve(context.Background(), res); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	waited, err := backend.WaitForResolution(context.Background(), item.Token)
	if err != nil {
		t.Fatalf("wait for resolution: %v", err)
	}
	if waited == nil || waited.Status != "approved" || waited.ResolvedBy != "approver-1" {
		t.Fatalf("unexpected resolution: %#v", waited)
	}

	snap, err = backend.Status(context.Background(), item.Token)
	if err != nil {
		t.Fatalf("status resolved: %v", err)
	}
	if snap.State != "approved" || snap.Resolution == nil {
		t.Fatalf("unexpected resolved snapshot: %#v", snap)
	}
}

func TestRedisBackendResolveConflictAndUnknown(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	backend := NewRedisBackend(RedisConfig{Client: client, Prefix: "test:defer"})
	t.Cleanup(func() { _ = backend.Close() })

	err := backend.Resolve(context.Background(), DeferResolution{Token: "missing", Approved: false})
	if !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("resolve missing err = %v, want ErrUnknownToken", err)
	}

	item := DeferItem{
		Token:     "tok-2",
		AgentID:   "agent-b",
		ToolID:    "tool-y",
		Reason:    "needs review",
		Priority:  "normal",
		CreatedAt: time.Now().UTC(),
		Deadline:  time.Now().UTC().Add(5 * time.Minute),
	}
	if err := backend.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := backend.Resolve(context.Background(), DeferResolution{Token: item.Token, Approved: false, Status: "denied"}); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	err = backend.Resolve(context.Background(), DeferResolution{Token: item.Token, Approved: true, Status: "approved"})
	if !errors.Is(err, ErrAlreadyResolved) {
		t.Fatalf("second resolve err = %v, want ErrAlreadyResolved", err)
	}
}
