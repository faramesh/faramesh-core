package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
)

const (
	fleetPushChannel = "faramesh:fleet:push"
	fleetKillChannel = "faramesh:fleet:kill"
	fleetRegistryKey = "faramesh:fleet:instances"
)

type fleetEvent struct {
	Action     string `json:"action"`
	InstanceID string `json:"instance_id"`
	Actor      string `json:"actor,omitempty"`
	Message    string `json:"message,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Timestamp  string `json:"timestamp"`
}

type fleetInstance struct {
	InstanceID string `json:"instance_id"`
	AgentID    string `json:"agent_id,omitempty"`
	Host       string `json:"host,omitempty"`
	PID        int    `json:"pid,omitempty"`
	Socket     string `json:"socket,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	Status     string `json:"status,omitempty"`
}

var (
	fleetRedisURL string
	fleetActor    string
	fleetMessage  string
	fleetReason   string
)

var fleetCmd = &cobra.Command{
	Use:   "fleet",
	Short: "Fleet control operations via Redis",
}

var fleetPushCmd = &cobra.Command{
	Use:   "push <instance-id>",
	Short: "Publish a fleet push event for an instance",
	Args:  cobra.ExactArgs(1),
	RunE:  runFleetPush,
}

var fleetKillCmd = &cobra.Command{
	Use:   "kill <instance-id>",
	Short: "Publish a fleet kill event for an instance",
	Args:  cobra.ExactArgs(1),
	RunE:  runFleetKill,
}

var fleetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered fleet instances from Redis",
	Args:  cobra.NoArgs,
	RunE:  runFleetList,
}

func init() {
	fleetCmd.PersistentFlags().StringVar(&fleetRedisURL, "fleet-redis-url", "", "Redis URL for fleet commands (env: FARAMESH_FLEET_REDIS_URL)")
	fleetPushCmd.Flags().StringVar(&fleetActor, "actor", "", "actor that initiated the push")
	fleetPushCmd.Flags().StringVar(&fleetMessage, "message", "", "optional push message")
	fleetKillCmd.Flags().StringVar(&fleetActor, "actor", "", "actor that initiated the kill")
	fleetKillCmd.Flags().StringVar(&fleetReason, "reason", "", "kill reason")
	fleetCmd.AddCommand(fleetPushCmd)
	fleetCmd.AddCommand(fleetKillCmd)
	fleetCmd.AddCommand(fleetListCmd)
}

func runFleetPush(cmd *cobra.Command, args []string) error {
	client, err := fleetRedisClient()
	if err != nil {
		return err
	}
	defer client.Close()

	instanceID := strings.TrimSpace(args[0])
	event := fleetEvent{
		Action:     "push",
		InstanceID: instanceID,
		Actor:      strings.TrimSpace(fleetActor),
		Message:    strings.TrimSpace(fleetMessage),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	return publishFleetEvent(cmd.Context(), client, fleetPushChannel, event)
}

func runFleetKill(cmd *cobra.Command, args []string) error {
	client, err := fleetRedisClient()
	if err != nil {
		return err
	}
	defer client.Close()

	instanceID := strings.TrimSpace(args[0])
	event := fleetEvent{
		Action:     "kill",
		InstanceID: instanceID,
		Actor:      strings.TrimSpace(fleetActor),
		Reason:     strings.TrimSpace(fleetReason),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := publishFleetEvent(cmd.Context(), client, fleetKillChannel, event); err != nil {
		return err
	}
	if err := client.HDel(cmd.Context(), fleetRegistryKey, instanceID).Err(); err != nil {
		return fmt.Errorf("remove instance from registry: %w", err)
	}
	return nil
}

func runFleetList(cmd *cobra.Command, _ []string) error {
	client, err := fleetRedisClient()
	if err != nil {
		return err
	}
	defer client.Close()

	rawEntries, err := client.HGetAll(cmd.Context(), fleetRegistryKey).Result()
	if err != nil {
		return fmt.Errorf("read fleet registry: %w", err)
	}
	instances, err := parseFleetRegistry(rawEntries)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(instances)
}

func fleetRedisClient() (*redis.Client, error) {
	url := strings.TrimSpace(fleetRedisURL)
	if url == "" {
		url = strings.TrimSpace(os.Getenv("FARAMESH_FLEET_REDIS_URL"))
	}
	if url == "" {
		return nil, fmt.Errorf("fleet redis url is required (--fleet-redis-url or FARAMESH_FLEET_REDIS_URL)")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse fleet redis url: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect fleet redis: %w", err)
	}
	return client, nil
}

func publishFleetEvent(ctx context.Context, client *redis.Client, channel string, event fleetEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal fleet event: %w", err)
	}
	if err := client.Publish(ctx, channel, payload).Err(); err != nil {
		return fmt.Errorf("publish fleet event: %w", err)
	}
	return nil
}

func parseFleetRegistry(rawEntries map[string]string) ([]fleetInstance, error) {
	instances := make([]fleetInstance, 0, len(rawEntries))
	for instanceID, raw := range rawEntries {
		var inst fleetInstance
		if err := json.Unmarshal([]byte(raw), &inst); err != nil {
			return nil, fmt.Errorf("decode fleet registry entry %q: %w", instanceID, err)
		}
		if strings.TrimSpace(inst.InstanceID) == "" {
			inst.InstanceID = instanceID
		}
		instances = append(instances, inst)
	}
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].InstanceID < instances[j].InstanceID
	})
	return instances, nil
}
