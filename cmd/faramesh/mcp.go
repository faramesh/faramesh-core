package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	gatewaymcp "github.com/faramesh/faramesh-core/internal/adapter/mcp"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP gateway operations",
}

var mcpWrapCmd = &cobra.Command{
	Use:                "wrap -- <mcp-server-command> [args...]",
	Short:              "Wrap a stdio MCP server with Faramesh governance",
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: false,
	RunE:               runMCPWrap,
}

var (
	mcpWrapPolicy  string
	mcpWrapAgentID string
)

func init() {
	mcpWrapCmd.Flags().StringVar(&mcpWrapPolicy, "policy", "policy.yaml", "path to policy YAML file")
	mcpWrapCmd.Flags().StringVar(&mcpWrapAgentID, "agent-id", "mcp-wrapper", "agent ID used for governed MCP tool calls")
	mcpCmd.AddCommand(mcpWrapCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPWrap(_ *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: faramesh mcp wrap -- <mcp-server-command> [args...]")
	}

	doc, version, err := policy.LoadFile(mcpWrapPolicy)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	log, _ := zap.NewProduction()
	defer log.Sync()

	gw, err := gatewaymcp.NewStdioGateway(pipeline, mcpWrapAgentID, log, args)
	if err != nil {
		return err
	}
	defer gw.Close()

	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for scanner.Scan() {
		var msg gatewaymcp.MCPMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			resp := gatewaymcp.MCPMessage{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &gatewaymcp.MCPError{
					Code:    -32700,
					Message: "parse error: invalid JSON-RPC request",
				},
			}
			b, _ := json.Marshal(resp)
			_, _ = writer.Write(append(b, '\n'))
			_ = writer.Flush()
			continue
		}

		resp, err := gw.ProcessRequest(msg)
		if err != nil {
			resp = gatewaymcp.MCPMessage{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Error: &gatewaymcp.MCPError{
					Code:    -32000,
					Message: err.Error(),
				},
			}
		}

		b, _ := json.Marshal(resp)
		_, _ = writer.Write(append(b, '\n'))
		_ = writer.Flush()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP input: %w", err)
	}
	return nil
}
