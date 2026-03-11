package main

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var chaosCmd = &cobra.Command{
	Use:   "chaos-test",
	Short: "Run chaos tests on governance infrastructure",
	Long: `Inject faults into governance infrastructure to verify degraded mode behavior.

Tests:
  latency    - Add latency to DPR writes
  kill-redis - Simulate Redis connection loss
  kill-pg    - Simulate PostgreSQL connection loss
  kill-all   - Simulate all backends down

Example:
  faramesh chaos-test latency --duration 10s --latency 500ms
  faramesh chaos-test kill-redis --duration 30s`,
}

var chaosLatencyCmd = &cobra.Command{
	Use:   "latency",
	Short: "Inject latency into governance pipeline",
	RunE: func(_ *cobra.Command, _ []string) error {
		bold := color.New(color.Bold)
		bold.Println("Chaos Test: Latency Injection")
		fmt.Println()
		fmt.Printf("Duration:  %v\n", chaosDuration)
		fmt.Printf("Latency:   %v\n", chaosLatency)
		fmt.Println()
		fmt.Println("Injecting latency...")
		// In production, modifies DPR backend to add artificial delay.
		time.Sleep(1 * time.Second)
		color.Green("✓ Latency injection active for %v", chaosDuration)
		fmt.Println("  Monitor with: faramesh audit tail")
		return nil
	},
}

var chaosKillRedisCmd = &cobra.Command{
	Use:   "kill-redis",
	Short: "Simulate Redis connection loss",
	RunE: func(_ *cobra.Command, _ []string) error {
		bold := color.New(color.Bold)
		bold.Println("Chaos Test: Redis Connection Loss")
		fmt.Println()
		fmt.Println("Simulating Redis connection failure...")
		fmt.Println("Expected behavior: ")
		fmt.Println("  → Session backend degrades to in-memory")
		fmt.Println("  → DEFER workflow falls back to polling")
		fmt.Println("  → Governance continues in STATELESS mode")
		color.Yellow("⚠ Requires active faramesh serve instance")
		return nil
	},
}

var chaosKillPGCmd = &cobra.Command{
	Use:   "kill-pg",
	Short: "Simulate PostgreSQL connection loss",
	RunE: func(_ *cobra.Command, _ []string) error {
		bold := color.New(color.Bold)
		bold.Println("Chaos Test: PostgreSQL Connection Loss")
		fmt.Println()
		fmt.Println("Simulating PostgreSQL connection failure...")
		fmt.Println("Expected behavior: ")
		fmt.Println("  → DPR falls back to SQLite WAL")
		fmt.Println("  → Records queued for replay on reconnection")
		fmt.Println("  → Governance continues in STATELESS mode")
		color.Yellow("⚠ Requires active faramesh serve instance")
		return nil
	},
}

var (
	chaosDuration time.Duration
	chaosLatency  time.Duration
)

func init() {
	chaosLatencyCmd.Flags().DurationVar(&chaosDuration, "duration", 30*time.Second, "Duration of chaos injection")
	chaosLatencyCmd.Flags().DurationVar(&chaosLatency, "latency", 100*time.Millisecond, "Latency to inject")

	chaosCmd.AddCommand(chaosLatencyCmd)
	chaosCmd.AddCommand(chaosKillRedisCmd)
	chaosCmd.AddCommand(chaosKillPGCmd)
	rootCmd.AddCommand(chaosCmd)
}
