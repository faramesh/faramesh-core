package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestPublishFleetEventPushPayload(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sub := client.Subscribe(ctx, fleetPushChannel)
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatalf("subscribe push channel: %v", err)
	}

	event := fleetEvent{
		Action:     "push",
		InstanceID: "inst-1",
		Actor:      "cli-test",
		Message:    "reload-policy",
		Timestamp:  "2026-03-21T00:00:00Z",
	}
	if err := publishFleetEvent(ctx, client, fleetPushChannel, event); err != nil {
		t.Fatalf("publish push event: %v", err)
	}

	msg, err := sub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("receive push event: %v", err)
	}

	var got fleetEvent
	if err := json.Unmarshal([]byte(msg.Payload), &got); err != nil {
		t.Fatalf("decode push payload: %v", err)
	}
	if got.Action != "push" || got.InstanceID != "inst-1" || got.Actor != "cli-test" || got.Message != "reload-policy" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestParseFleetRegistry(t *testing.T) {
	raw := map[string]string{
		"inst-b": `{"instance_id":"inst-b","status":"running","agent_id":"agent-b"}`,
		"inst-a": `{"status":"running","agent_id":"agent-a"}`,
	}

	instances, err := parseFleetRegistry(raw)
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(instances))
	}
	if instances[0].InstanceID != "inst-a" || instances[1].InstanceID != "inst-b" {
		t.Fatalf("expected sorted instance IDs, got %+v", instances)
	}
	if instances[0].AgentID != "agent-a" {
		t.Fatalf("expected agent-a in first entry, got %+v", instances[0])
	}
}
