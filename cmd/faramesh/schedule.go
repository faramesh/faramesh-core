package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scheduled tool executions",
}

var (
	schedCreateTool   string
	schedCreateArgs   string
	schedCreateAgent  string
	schedCreateAt     string
	schedCreatePolicy string
	schedCreateReeval bool
)

var scheduleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new scheduled tool execution",
	Args:  cobra.NoArgs,
	RunE:  runScheduleCreate,
}

var schedListAgent string

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scheduled executions",
	Args:  cobra.NoArgs,
	RunE:  runScheduleList,
}

var scheduleInspectCmd = &cobra.Command{
	Use:   "inspect <schedule-id>",
	Short: "Inspect a scheduled execution by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runScheduleInspect,
}

var scheduleCancelCmd = &cobra.Command{
	Use:   "cancel <schedule-id>",
	Short: "Cancel a scheduled execution",
	Args:  cobra.ExactArgs(1),
	RunE:  runScheduleCancel,
}

var scheduleApproveCmd = &cobra.Command{
	Use:   "approve <schedule-id>",
	Short: "Approve a pending scheduled execution",
	Args:  cobra.ExactArgs(1),
	RunE:  runScheduleApprove,
}

var schedulePendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending scheduled executions awaiting approval",
	Args:  cobra.NoArgs,
	RunE:  runSchedulePending,
}

var schedHistoryWindow string

var scheduleHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show execution history for scheduled tool calls",
	Args:  cobra.NoArgs,
	RunE:  runScheduleHistory,
}

func init() {
	scheduleCreateCmd.Flags().StringVar(&schedCreateTool, "tool", "", "tool identifier to schedule")
	scheduleCreateCmd.Flags().StringVar(&schedCreateArgs, "args", "", "tool arguments as JSON object")
	scheduleCreateCmd.Flags().StringVar(&schedCreateAgent, "agent", "", "agent identifier")
	scheduleCreateCmd.Flags().StringVar(&schedCreateAt, "at", "", "execution time (RFC3339 or relative, e.g. +30m)")
	scheduleCreateCmd.Flags().StringVar(&schedCreatePolicy, "policy", "", "policy to evaluate against")
	scheduleCreateCmd.Flags().BoolVar(&schedCreateReeval, "reeval", false, "re-evaluate policy at execution time")
	_ = scheduleCreateCmd.MarkFlagRequired("tool")
	_ = scheduleCreateCmd.MarkFlagRequired("agent")

	scheduleListCmd.Flags().StringVar(&schedListAgent, "agent", "", "filter by agent identifier")

	scheduleHistoryCmd.Flags().StringVar(&schedHistoryWindow, "window", "24h", "time window for history")

	scheduleCmd.AddCommand(
		scheduleCreateCmd, scheduleListCmd, scheduleInspectCmd,
		scheduleCancelCmd, scheduleApproveCmd, schedulePendingCmd,
		scheduleHistoryCmd,
	)
	rootCmd.AddCommand(scheduleCmd)
}

func runScheduleCreate(_ *cobra.Command, _ []string) error {
	body := map[string]any{
		"tool":   schedCreateTool,
		"agent":  schedCreateAgent,
		"reeval": schedCreateReeval,
	}
	if schedCreateAt != "" {
		body["at"] = schedCreateAt
	}
	if schedCreatePolicy != "" {
		body["policy"] = schedCreatePolicy
	}
	if schedCreateArgs != "" {
		var parsed any
		if err := json.Unmarshal([]byte(schedCreateArgs), &parsed); err != nil {
			return fmt.Errorf("--args must be valid JSON: %w", err)
		}
		body["args"] = parsed
	}
	resp, err := daemonPost("/api/v1/schedule/create", body)
	if err != nil {
		return err
	}
	printResponse("Schedule Created", resp)
	return nil
}

func runScheduleList(_ *cobra.Command, _ []string) error {
	resp, err := daemonGetWithQuery("/api/v1/schedule/list", map[string]string{
		"agent": schedListAgent,
	})
	if err != nil {
		return err
	}
	printResponse("Scheduled Executions", resp)
	return nil
}

func runScheduleInspect(_ *cobra.Command, args []string) error {
	resp, err := daemonGetWithQuery("/api/v1/schedule/inspect", map[string]string{
		"id": args[0],
	})
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Schedule — %s", args[0]), resp)
	return nil
}

func runScheduleCancel(_ *cobra.Command, args []string) error {
	resp, err := daemonPost("/api/v1/schedule/cancel", map[string]any{
		"schedule_id": args[0],
	})
	if err != nil {
		return err
	}
	printResponse("Schedule Cancelled", resp)
	return nil
}

func runScheduleApprove(_ *cobra.Command, args []string) error {
	resp, err := daemonPost("/api/v1/schedule/approve", map[string]any{
		"schedule_id": args[0],
	})
	if err != nil {
		return err
	}
	printResponse("Schedule Approved", resp)
	return nil
}

func runSchedulePending(_ *cobra.Command, _ []string) error {
	resp, err := daemonGet("/api/v1/schedule/pending")
	if err != nil {
		return err
	}
	printResponse("Pending Schedules", resp)
	return nil
}

func runScheduleHistory(_ *cobra.Command, _ []string) error {
	resp, err := daemonGetWithQuery("/api/v1/schedule/history", map[string]string{
		"window": schedHistoryWindow,
	})
	if err != nil {
		return err
	}
	printResponse("Schedule History", resp)
	return nil
}
