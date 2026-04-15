package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/adapter/mcp"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP gateway helpers (stdio transport)",
}

var (
	mcpWrapPolicy     string
	mcpWrapAgent      string
	mcpWrapDataDir    string
	mcpWrapDPRHMACKey string
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
	mcpWrapCmd.Flags().StringVar(&mcpWrapDataDir, "data-dir", "", "directory for WAL, DPR SQLite, and tool inventory (default: $TMPDIR/faramesh-mcp-wrap)")
	mcpWrapCmd.Flags().StringVar(&mcpWrapDPRHMACKey, "dpr-hmac-key", "", "HMAC secret for approval envelopes and DPR replay (optional; should match policy policy-replay --dpr-hmac-key)")
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

	dataDir := defaultMCPWrapDataDir(mcpWrapDataDir)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	wal, err := dpr.OpenWAL(filepath.Join(dataDir, "faramesh.wal"))
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer wal.Close()
	store, err := dpr.OpenStore(filepath.Join(dataDir, "faramesh.db"))
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()
	inventoryStore, err := toolinventory.OpenStore(filepath.Join(dataDir, "faramesh-tool-inventory.db"))
	if err != nil {
		return fmt.Errorf("open tool inventory store: %w", err)
	}
	defer inventoryStore.Close()
	dprQueue := jobs.NewInprocDPRQueue(store, jobs.InprocDPRQueueConfig{})
	defer dprQueue.Close()

	pcfg := core.Config{
		Engine:        policy.NewAtomicEngine(eng),
		WAL:           wal,
		Store:         store,
		DPRQueue:      dprQueue,
		Sessions:      session.NewManager(),
		Defers:        deferwork.NewWorkflow(""),
		ToolInventory: inventoryStore,
	}
	if k := strings.TrimSpace(mcpWrapDPRHMACKey); k != "" {
		pcfg.HMACKey = []byte(k)
	}
	pipe := core.NewPipeline(pcfg)

	gw, err := mcp.NewStdioGateway(pipe, agentID, log, args)
	if err != nil {
		return err
	}
	defer gw.Close()

	stdinLines := make(chan []byte, 64)
	stdinErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			stdinLines <- line
		}
		if err := scanner.Err(); err != nil {
			stdinErr <- err
		}
		close(stdinLines)
		close(stdinErr)
	}()

	for {
		select {
		case line, ok := <-stdinLines:
			if !ok {
				return nil
			}
			out, err := gw.ProcessStdioLine(line)
			if err != nil {
				if writeErr := writeJSONRPCErrorLine(-32600, "invalid JSON-RPC: "+err.Error()); writeErr != nil {
					return writeErr
				}
				continue
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
		case outbound, ok := <-gw.Outbound():
			if !ok {
				return nil
			}
			if len(outbound) == 0 {
				continue
			}
			if _, err := os.Stdout.Write(outbound); err != nil {
				return err
			}
			if _, err := os.Stdout.Write([]byte("\n")); err != nil {
				return err
			}
		case err, ok := <-stdinErr:
			if !ok {
				stdinErr = nil
				continue
			}
			if err != nil {
				return err
			}
		}
	}
}

func defaultMCPWrapDataDir(v string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return filepath.Join(os.TempDir(), "faramesh-mcp-wrap")
}

func writeJSONRPCErrorLine(code int, message string) error {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(b); err != nil {
		return err
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}
