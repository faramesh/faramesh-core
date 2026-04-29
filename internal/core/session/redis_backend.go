package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend implements Backend using Redis.
// All threshold checks use atomic Lua scripts to prevent TOCTOU races.
// Key layout:
//
//	faramesh:sess:{agentID}:calls     — INT64 call counter
//	faramesh:sess:{agentID}:cost:sess — FLOAT64 session cost
//	faramesh:sess:{agentID}:cost:day:{date} — FLOAT64 daily cost
//	faramesh:sess:{agentID}:history   — LIST of JSON-encoded HistoryEntry
//	faramesh:sess:{agentID}:killed    — "1" if kill switch active
type RedisBackend struct {
	client     redis.Cmdable
	keyPrefix  string
	sessionTTL time.Duration // TTL for session-scoped keys
	dailyTTL   time.Duration // TTL for daily cost keys
}

// RedisConfig holds configuration for the Redis backend.
type RedisConfig struct {
	// Client is a pre-configured Redis client (may be standalone or cluster).
	Client redis.Cmdable

	// KeyPrefix is prepended to all Redis keys (default: "faramesh:sess:").
	KeyPrefix string

	// SessionTTL is the expiration for session-scoped keys (default: 24h).
	SessionTTL time.Duration

	// DailyTTL is the expiration for daily cost keys (default: 48h).
	DailyTTL time.Duration
}

// NewRedisBackend creates a Redis-backed session state implementation.
func NewRedisBackend(cfg RedisConfig) *RedisBackend {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "faramesh:sess:"
	}
	sessTTL := cfg.SessionTTL
	if sessTTL == 0 {
		sessTTL = 24 * time.Hour
	}
	dayTTL := cfg.DailyTTL
	if dayTTL == 0 {
		dayTTL = 48 * time.Hour
	}
	return &RedisBackend{
		client:     cfg.Client,
		keyPrefix:  prefix,
		sessionTTL: sessTTL,
		dailyTTL:   dayTTL,
	}
}

func (b *RedisBackend) key(agentID, suffix string) string {
	return b.keyPrefix + agentID + ":" + suffix
}

func (b *RedisBackend) IncrCallCount(ctx context.Context, agentID, _ string) (int64, error) {
	k := b.key(agentID, "calls")
	val, err := b.client.Incr(ctx, k).Result()
	if err != nil {
		return 0, fmt.Errorf("redis incr call count: %w", err)
	}
	b.client.Expire(ctx, k, b.sessionTTL)
	return val, nil
}

func (b *RedisBackend) GetCallCount(ctx context.Context, agentID, _ string) (int64, error) {
	val, err := b.client.Get(ctx, b.key(agentID, "calls")).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (b *RedisBackend) AddCost(ctx context.Context, agentID, _ string, costUSD float64) (float64, float64, error) {
	sessKey := b.key(agentID, "cost:sess")
	dayKey := b.key(agentID, "cost:day:"+todayUTC())

	pipe := b.client.Pipeline()
	sessCmd := pipe.IncrByFloat(ctx, sessKey, costUSD)
	dayCmd := pipe.IncrByFloat(ctx, dayKey, costUSD)
	pipe.Expire(ctx, sessKey, b.sessionTTL)
	pipe.Expire(ctx, dayKey, b.dailyTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, fmt.Errorf("redis add cost: %w", err)
	}
	return sessCmd.Val(), dayCmd.Val(), nil
}

func (b *RedisBackend) GetSessionCost(ctx context.Context, agentID, _ string) (float64, error) {
	val, err := b.client.Get(ctx, b.key(agentID, "cost:sess")).Float64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (b *RedisBackend) GetDailyCost(ctx context.Context, agentID string) (float64, error) {
	val, err := b.client.Get(ctx, b.key(agentID, "cost:day:"+todayUTC())).Float64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (b *RedisBackend) RecordHistory(ctx context.Context, agentID, _ string, entry HistoryEntry, maxEntries int) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	k := b.key(agentID, "history")
	pipe := b.client.Pipeline()
	pipe.LPush(ctx, k, data)
	pipe.LTrim(ctx, k, 0, int64(maxEntries-1))
	pipe.Expire(ctx, k, b.sessionTTL)
	_, err = pipe.Exec(ctx)
	return err
}

func (b *RedisBackend) GetHistory(ctx context.Context, agentID, _ string, limit int) ([]HistoryEntry, error) {
	vals, err := b.client.LRange(ctx, b.key(agentID, "history"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	entries := make([]HistoryEntry, 0, len(vals))
	for _, v := range vals {
		var e HistoryEntry
		if err := json.Unmarshal([]byte(v), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (b *RedisBackend) SetKillSwitch(ctx context.Context, agentID string) error {
	// Kill switch has no TTL — must be explicitly cleared.
	return b.client.Set(ctx, b.key(agentID, "killed"), "1", 0).Err()
}

func (b *RedisBackend) IsKilled(ctx context.Context, agentID string) (bool, error) {
	val, err := b.client.Get(ctx, b.key(agentID, "killed")).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}

// checkAndReserveLua atomically checks budget + reserves cost.
// KEYS[1] = session cost key, KEYS[2] = daily cost key
// ARGV[1] = costUSD, ARGV[2] = sessionLimit, ARGV[3] = dailyLimit
// ARGV[4] = sessionTTL seconds, ARGV[5] = dailyTTL seconds
// Returns 1 if reserved, 0 if budget exceeded.
var checkAndReserveLua = redis.NewScript(`
local cost = tonumber(ARGV[1])
local sess_limit = tonumber(ARGV[2])
local day_limit = tonumber(ARGV[3])
local sess_ttl = tonumber(ARGV[4])
local day_ttl = tonumber(ARGV[5])

local sess_cost = tonumber(redis.call('GET', KEYS[1]) or '0')
local day_cost = tonumber(redis.call('GET', KEYS[2]) or '0')

if sess_limit > 0 and (sess_cost + cost) > sess_limit then return 0 end
if day_limit > 0 and (day_cost + cost) > day_limit then return 0 end

redis.call('INCRBYFLOAT', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], sess_ttl)
redis.call('INCRBYFLOAT', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[2], day_ttl)
return 1
`)

func (b *RedisBackend) CheckAndReserveCost(ctx context.Context, agentID, _ string,
	costUSD, sessionLimit, dailyLimit float64) (bool, error) {
	sessKey := b.key(agentID, "cost:sess")
	dayKey := b.key(agentID, "cost:day:"+todayUTC())

	result, err := checkAndReserveLua.Run(ctx, b.client,
		[]string{sessKey, dayKey},
		strconv.FormatFloat(costUSD, 'f', -1, 64),
		strconv.FormatFloat(sessionLimit, 'f', -1, 64),
		strconv.FormatFloat(dailyLimit, 'f', -1, 64),
		int64(b.sessionTTL.Seconds()),
		int64(b.dailyTTL.Seconds()),
	).Int64()
	if err != nil {
		return false, fmt.Errorf("redis check-and-reserve: %w", err)
	}
	return result == 1, nil
}

func (b *RedisBackend) ConfirmCost(_ context.Context, _, _ string, _ float64) error {
	// Cost already reserved atomically — no separate confirm needed.
	return nil
}

// rollbackLua atomically subtracts cost from both session and daily counters.
var rollbackLua = redis.NewScript(`
local cost = tonumber(ARGV[1])
redis.call('INCRBYFLOAT', KEYS[1], -cost)
redis.call('INCRBYFLOAT', KEYS[2], -cost)
return 1
`)

func (b *RedisBackend) RollbackCost(ctx context.Context, agentID, _ string, costUSD float64) error {
	sessKey := b.key(agentID, "cost:sess")
	dayKey := b.key(agentID, "cost:day:"+todayUTC())
	return rollbackLua.Run(ctx, b.client,
		[]string{sessKey, dayKey},
		strconv.FormatFloat(costUSD, 'f', -1, 64),
	).Err()
}

func (b *RedisBackend) Close() error {
	if c, ok := b.client.(*redis.Client); ok {
		return c.Close()
	}
	return nil
}

func todayUTC() string {
	return time.Now().UTC().Format("2006-01-02")
}
