package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/adapter/mcp"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP gateway helpers (stdio transport)",
}

var (
	mcpWrapPolicy string
	mcpWrapAgent  string
)

var mcpWrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a stdio MCP server with governance (JSON-RPC over stdin/stdout)",
	Long: `Runs the given command as a subprocess and proxies MCP JSON-RPC between the
client (stdin) and the server (subprocess). Each tool call is evaluated against
the policy before it reaches the upstream server.

  faramesh mcp wrap --policy policy.yaml -- node ./mcp-server.js

Lines may be a single JSON-RPC object or a JSON-RPC batch array (same semantics
as the HTTP MCP gateway).`,
	Args: cobra.MinimumNArgs(1),
	RunE: runMCPWrap,
}

func init() {
	mcpWrapCmd.Flags().StringVar(&mcpWrapPolicy, "policy", "policy.yaml", "path to policy YAML")
	mcpWrapCmd.Flags().StringVar(&mcpWrapAgent, "agent-id", "", "agent id for policy evaluation (default: policy agent-id)")
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpWrapCmd)
}

func runMCPWrap(_ *cobra.Command, args []string) error {
	doc, ver, err := policy.LoadFile(mcpWrapPolicy)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	agentID := strings.TrimSpace(mcpWrapAgent)
	if agentID == "" {
		agentID = doc.AgentID
	}
	if agentID == "" {
		agentID = "mcp-wrap"
	}
	log, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer log.Sync()

	pipe := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	gw, err := mcp.NewStdioGateway(pipe, agentID, log, args)
	if err != nil {
		return err
	}
	defer gw.Close()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		out, err := gw.ProcessStdioLine(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("json-rpc line: %w", err)
		}
		if len(out) == 0 {
			continue
		}
		if _, err := os.Stdout.Write(out); err != nil {
			return err
		}
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
