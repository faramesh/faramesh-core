package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisBackendCallCountAndCost(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(func() { mr.Close() })

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	b := NewRedisBackend(RedisConfig{Client: rdb, KeyPrefix: "test:sess:"})
	ctx := context.Background()
	agent := "agent-redis-1"
	sess := "sess-1"

	n, err := b.IncrCallCount(ctx, agent, sess)
	if err != nil || n != 1 {
		t.Fatalf("IncrCallCount: n=%d err=%v", n, err)
	}
	n2, err := b.GetCallCount(ctx, agent, sess)
	if err != nil || n2 != 1 {
		t.Fatalf("GetCallCount: n=%d err=%v", n2, err)
	}

	sessCost, dayCost, err := b.AddCost(ctx, agent, sess, 1.5)
	if err != nil {
		t.Fatal(err)
	}
	if sessCost < 1.4 || dayCost < 1.4 {
		t.Fatalf("expected ~1.5 cost, sess=%v day=%v", sessCost, dayCost)
	}
	gotSess, err := b.GetSessionCost(ctx, agent, sess)
	if err != nil || gotSess < 1.4 {
		t.Fatalf("GetSessionCost: %v err=%v", gotSess, err)
	}
	gotDay, err := b.GetDailyCost(ctx, agent)
	if err != nil || gotDay < 1.4 {
		t.Fatalf("GetDailyCost: %v err=%v", gotDay, err)
	}
}

func TestRedisBackendHistoryAndKillSwitch(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(func() { mr.Close() })
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	b := NewRedisBackend(RedisConfig{Client: rdb})
	ctx := context.Background()
	agent := "agent-redis-2"
	sess := "sess-2"
	ts := time.Now().UTC().Truncate(time.Second)

	if err := b.RecordHistory(ctx, agent, sess, HistoryEntry{ToolID: "t1", Effect: "PERMIT", Timestamp: ts}, 10); err != nil {
		t.Fatal(err)
	}
	hist, err := b.GetHistory(ctx, agent, sess, 5)
	if err != nil || len(hist) != 1 || hist[0].ToolID != "t1" {
		t.Fatalf("history: %+v err=%v", hist, err)
	}

	if err := b.SetKillSwitch(ctx, agent); err != nil {
		t.Fatal(err)
	}
	killed, err := b.IsKilled(ctx, agent)
	if err != nil || !killed {
		t.Fatalf("killed=%v err=%v", killed, err)
	}
}

func TestRedisBackendCheckAndReserveCost(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(func() { mr.Close() })
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	b := NewRedisBackend(RedisConfig{Client: rdb})
	ctx := context.Background()
	agent := "agent-redis-3"

	ok, err := b.CheckAndReserveCost(ctx, agent, "s", 10, 100, 100)
	if err != nil || !ok {
		t.Fatalf("CheckAndReserveCost first: ok=%v err=%v", ok, err)
	}
	ok2, err := b.CheckAndReserveCost(ctx, agent, "s", 95, 100, 100)
	if err != nil || ok2 {
		t.Fatalf("CheckAndReserveCost should exceed session: ok=%v err=%v", ok2, err)
	}
}
