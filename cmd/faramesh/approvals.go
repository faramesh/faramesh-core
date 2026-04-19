package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	approvalsCmd = &cobra.Command{
		Use:   "approvals",
		Short: "Resolve deferred actions with human approvals",
		Long:  "List pending approvals, inspect approval context, approve or deny decisions, and open the approvals inbox UI.",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsList,
	}

	approvalsListCmd = &cobra.Command{
		Use:   "list",
		Short: "List pending approvals",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsList,
	}

	approvalsPendingCmd = &cobra.Command{
		Use:   "pending",
		Short: "Alias for approvals list",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsList,
	}

	approvalsShowCmd = &cobra.Command{
		Use:     "show <approval-id>",
		Aliases: []string{"inspect"},
		Short:   "Show status and context for one approval",
		Args:    cobra.ExactArgs(1),
		RunE:    runApprovalsShow,
	}

	approvalsWatchCmd = &cobra.Command{
		Use:   "watch",
		Short: "Watch the approval queue in real time",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsWatch,
	}

	approvalsHistoryCmd = &cobra.Command{
		Use:   "history",
		Short: "Show approval history for one agent",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsHistory,
	}

	approvalsApproveCmd = &cobra.Command{
		Use:   "approve <approval-id>",
		Short: "Approve a deferred action",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return sendApproval(args[0], true, strings.TrimSpace(approvalsReason))
		},
	}

	approvalsDenyCmd = &cobra.Command{
		Use:   "deny <approval-id>",
		Short: "Deny a deferred action",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return sendApproval(args[0], false, strings.TrimSpace(approvalsReason))
		},
	}

	approvalsUICmd = &cobra.Command{
		Use:   "ui",
		Short: "Show or open the approvals inbox UI",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsUI,
	}

	approvalsAgentFilter   string
	approvalsReason        string
	approvalsWatchAgent    string
	approvalsWatchInterval time.Duration
	approvalsWatchOnce     bool
	approvalsHistoryAgent  string
	approvalsHistoryWindow string
	approvalsUIURL         string
	approvalsUIOpen        bool
	approvalsUIRequireLive bool
	approvalsUIBind        string
	approvalsOutputJSON    bool
)

func init() {
	approvalsListCmd.Flags().StringVar(&approvalsAgentFilter, "agent", "", "filter by agent ID")
	approvalsCmd.PersistentFlags().BoolVar(&approvalsOutputJSON, "json", false, "output raw JSON instead of human-readable summaries")
	approvalsShowCmd.Flags().StringVar(&approvalsAgentFilter, "agent", "", "agent hint for status polling")
	approvalsWatchCmd.Flags().StringVar(&approvalsWatchAgent, "agent", "", "filter by agent ID")
	approvalsWatchCmd.Flags().DurationVar(&approvalsWatchInterval, "interval", 2*time.Second, "poll interval")
	approvalsWatchCmd.Flags().BoolVar(&approvalsWatchOnce, "once", false, "print one snapshot and exit")
	approvalsHistoryCmd.Flags().StringVar(&approvalsHistoryAgent, "agent", "", "agent ID for history query")
	approvalsHistoryCmd.Flags().StringVar(&approvalsHistoryWindow, "window", "", "time window (for example 1h, 24h)")
	approvalsApproveCmd.Flags().StringVar(&approvalsReason, "reason", "", "decision reason captured in audit evidence")
	approvalsDenyCmd.Flags().StringVar(&approvalsReason, "reason", "", "decision reason captured in audit evidence")
	approvalsUICmd.Flags().StringVar(&approvalsUIURL, "url", "", "approvals UI URL override")
	approvalsUICmd.Flags().BoolVar(&approvalsUIOpen, "open", false, "open approvals UI in default browser")
	approvalsUICmd.Flags().BoolVar(&approvalsUIRequireLive, "require-live", false, "fail if approvals UI endpoint is unreachable")
	approvalsUICmd.Flags().StringVar(&approvalsUIBind, "bind", "127.0.0.1:39090", "bind address for built-in approvals UI fallback server")

	approvalsCmd.AddCommand(approvalsListCmd)
	approvalsCmd.AddCommand(approvalsPendingCmd)
	approvalsCmd.AddCommand(approvalsShowCmd)
	approvalsCmd.AddCommand(approvalsWatchCmd)
	approvalsCmd.AddCommand(approvalsHistoryCmd)
	approvalsCmd.AddCommand(approvalsApproveCmd)
	approvalsCmd.AddCommand(approvalsDenyCmd)
	approvalsCmd.AddCommand(approvalsUICmd)

	rootCmd.AddCommand(approvalsCmd)
}

func runApprovalsHistory(_ *cobra.Command, _ []string) error {
	agentID := strings.TrimSpace(approvalsHistoryAgent)
	if agentID == "" {
		agentID = strings.TrimSpace(approvalsAgentFilter)
	}
	if agentID == "" {
		return fmt.Errorf("agent ID is required (use --agent)")
	}

	socketReq := map[string]any{
		"type": "agent",
		"op":   "history",
		"id":   agentID,
	}
	query := map[string]string{"id": agentID}
	if window := strings.TrimSpace(approvalsHistoryWindow); window != "" {
		socketReq["window"] = window
		query["window"] = window
	}

	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), socketReq)
	if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
		raw, err = daemonGetWithQuery("/api/v1/agent/history", query)
	}
	if err != nil {
		return wrapApprovalsConnectivityError(err)
	}

	if approvalsOutputJSON {
		printResponse("Approval History", normalizeApprovalsJSON(raw))
		return nil
	}

	printHeader("Approval History")
	printJSON(normalizeApprovalsJSON(raw))
	return nil
}
func runApprovalsList(_ *cobra.Command, _ []string) error {
	items, err := fetchPendingApprovals(approvalsAgentFilter)
	if err != nil {
		return wrapApprovalsConnectivityError(err)
	}

	if approvalsOutputJSON {
		payload := map[string]any{"count": len(items), "items": items}
		raw, _ := json.Marshal(payload)
		printResponse("Approval Queue", raw)
		return nil
	}

	printApprovalsQueue("Approval Queue", items, strings.TrimSpace(approvalsAgentFilter))
	return nil
}

func runApprovalsShow(_ *cobra.Command, args []string) error {
	token := strings.TrimSpace(args[0])
	if token == "" {
		return fmt.Errorf("approval ID is required")
	}

	items, err := fetchPendingApprovals("")
	if err != nil {
		return wrapApprovalsConnectivityError(err)
	}

	var match map[string]string
	for _, item := range items {
		if approvalTokenFromItem(item) == token {
			match = item
			break
		}
	}

	agentHint := strings.TrimSpace(approvalsAgentFilter)
	if agentHint == "" && match != nil {
		agentHint = strings.TrimSpace(match["agent_id"])
	}

	status, statusErr := requestDeferStatus(token, agentHint)
	statusValue := strings.TrimSpace(fmt.Sprint(status["status"]))
	if statusValue == "" {
		statusValue = "unknown"
	}

	if match == nil && statusValue == "unknown" {
		if statusErr != nil {
			return statusErr
		}
		return fmt.Errorf("approval ID not found: %s", token)
	}

	out := map[string]any{
		"approval_id": token,
		"status":      statusValue,
		"pending":     match != nil,
	}
	if match != nil {
		out["item"] = match
	}
	if statusErr != nil {
		out["status_warning"] = statusErr.Error()
	}

	raw, _ := json.Marshal(out)
	if approvalsOutputJSON {
		printResponse("Approval Detail", raw)
		return nil
	}
	printApprovalDetail(token, statusValue, match, statusErr)
	return nil
}

func runApprovalsWatch(_ *cobra.Command, _ []string) error {
	interval := approvalsWatchInterval
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}

	lastFingerprint := ""
	for {
		items, err := fetchPendingApprovals(approvalsWatchAgent)
		if err != nil {
			return wrapApprovalsConnectivityError(err)
		}

		fingerprintBytes, _ := json.Marshal(items)
		fingerprint := string(fingerprintBytes)
		if fingerprint != lastFingerprint {
			if approvalsOutputJSON {
				payload := map[string]any{
					"timestamp": time.Now().UTC().Format(time.RFC3339),
					"count":     len(items),
					"items":     items,
				}
				raw, _ := json.Marshal(payload)
				printResponse("Approval Queue Watch", raw)
			} else {
				printApprovalsWatchSnapshot(items, approvalsWatchAgent)
			}
			lastFingerprint = fingerprint
		}

		if approvalsWatchOnce {
			return nil
		}
		time.Sleep(interval)
	}
}

func runApprovalsUI(_ *cobra.Command, _ []string) error {
	targetURL, err := resolveApprovalsURL(approvalsUIURL)
	if err != nil {
		return err
	}

	if targetURL != "" && httpEndpointHealthy(targetURL) {
		fmt.Printf("Approvals UI: %s\n", targetURL)
		if approvalsUIOpen {
			if err := openBrowserURL(targetURL); err != nil {
				return err
			}
		}
		return nil
	}

	if targetURL != "" && approvalsUIRequireLive {
		return fmt.Errorf("approvals UI is not reachable at %s (remove --require-live to launch the built-in approvals inbox)", targetURL)
	}

	builtInURL, serveErr := serveEmbeddedApprovalsUI(strings.TrimSpace(approvalsUIBind), approvalsUIOpen)
	if serveErr != nil {
		if targetURL != "" {
			return fmt.Errorf("dashboard approvals UI unavailable (%s) and built-in fallback failed: %w", targetURL, serveErr)
		}
		return fmt.Errorf("built-in approvals UI fallback failed: %w", serveErr)
	}

	fmt.Printf("Approvals UI: %s\n", builtInURL)
	return nil
}

func resolveApprovalsURL(raw string) (string, error) {
	if explicit := strings.TrimSpace(raw); explicit != "" {
		return explicit, nil
	}

	stateDir, err := resolveRuntimeStateDir("")
	if err == nil {
		metaPath := filepath.Join(stateDir, "runtime.json")
		if state, readErr := readRuntimeStartState(metaPath); readErr == nil {
			if state.Dashboard != nil {
				if base := strings.TrimRight(strings.TrimSpace(state.Dashboard.URL), "/"); base != "" {
					return base + "/approvals", nil
				}
			}
		}
	}

	defaultURL := "http://127.0.0.1:3000/approvals"
	if httpEndpointHealthy(defaultURL) {
		return defaultURL, nil
	}

	return "", nil
}

func resolveApprovalsSocketPath() string {
	return resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
}

func serveEmbeddedApprovalsUI(bind string, openBrowser bool) (string, error) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		bind = "127.0.0.1:39090"
	}

	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return "", fmt.Errorf("listen %s: %w", bind, err)
	}

	httpURL := "http://" + listener.Addr().String() + "/approvals"
	if openBrowser {
		if err := openBrowserURL(httpURL); err != nil {
			_ = listener.Close()
			return "", err
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/approvals", http.StatusFound)
	})
	mux.HandleFunc("/approvals", renderApprovalsPage)
	mux.HandleFunc("/approvals/decision", handleApprovalsDecision)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"ok\":true}"))
	})

	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           mux,
	}

	fmt.Printf("Approvals UI fallback is running at %s (Ctrl+C to stop)\n", httpURL)
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return "", err
	}
	return httpURL, nil
}

func renderApprovalsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	items, err := fetchPendingApprovals("")
	statusMsg := strings.TrimSpace(r.URL.Query().Get("status"))
	message := strings.TrimSpace(r.URL.Query().Get("message"))
	pendingCount := len(items)

	_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Faramesh Approvals</title>
	<style>
		:root {
			--bg0: #0f172a;
			--bg1: #111827;
			--card: #ffffff;
			--ink: #0f172a;
			--muted: #475569;
			--line: #e2e8f0;
			--ok: #047857;
			--okbg: #ecfdf5;
			--err: #991b1b;
			--errbg: #fef2f2;
			--chip: #e2e8f0;
			--chipInk: #1e293b;
		}
		* { box-sizing: border-box; }
		body {
			margin: 0;
			color: var(--ink);
			font-family: "Avenir Next", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
			background: radial-gradient(1200px 500px at 15%% -20%%, #1d4ed8 0%%, transparent 55%%),
									radial-gradient(1200px 500px at 90%% -10%%, #0f766e 0%%, transparent 50%%),
									linear-gradient(180deg, var(--bg0), var(--bg1));
			min-height: 100vh;
		}
		main {
			max-width: 1080px;
			margin: 0 auto;
			padding: 28px 20px 36px;
		}
		.hero {
			background: rgba(255,255,255,0.08);
			border: 1px solid rgba(255,255,255,0.18);
			color: #f8fafc;
			border-radius: 16px;
			padding: 18px 20px;
			margin-bottom: 16px;
			backdrop-filter: blur(6px);
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 12px;
			flex-wrap: wrap;
		}
		h1 { margin: 0; font-size: 22px; letter-spacing: 0.2px; }
		.sub { margin: 6px 0 0; color: #e2e8f0; font-size: 14px; }
		.count {
			background: rgba(255,255,255,0.16);
			border: 1px solid rgba(255,255,255,0.25);
			border-radius: 999px;
			padding: 6px 12px;
			font-size: 13px;
			font-weight: 700;
			color: #f8fafc;
		}
		.msg { padding: 11px 14px; border-radius: 10px; margin-bottom: 12px; font-size: 14px; }
		.ok { background: var(--okbg); color: var(--ok); border: 1px solid #a7f3d0; }
		.err { background: var(--errbg); color: var(--err); border: 1px solid #fecaca; }
		.toolbar { display: flex; justify-content: flex-end; margin: 10px 0 14px; }
		.refresh {
			display: inline-block;
			background: #0f172a;
			color: #f8fafc;
			text-decoration: none;
			border-radius: 10px;
			padding: 8px 12px;
			font-size: 13px;
			font-weight: 700;
			border: 1px solid rgba(255,255,255,0.2);
		}
		.grid { display: grid; grid-template-columns: 1fr; gap: 12px; }
		.card {
			background: var(--card);
			border: 1px solid var(--line);
			border-radius: 14px;
			padding: 16px;
			box-shadow: 0 8px 20px rgba(15, 23, 42, 0.08);
		}
		.row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
		.pill {
			display: inline-block;
			background: var(--chip);
			color: var(--chipInk);
			border-radius: 999px;
			padding: 4px 10px;
			font-size: 12px;
			font-weight: 700;
		}
		.kv { margin: 6px 0; font-size: 14px; color: #334155; }
		.reason {
			width: 100%%;
			margin-top: 10px;
			padding: 9px 10px;
			border: 1px solid #cbd5e1;
			border-radius: 10px;
			font-size: 14px;
		}
		.actions { display: flex; gap: 8px; margin-top: 10px; }
		.btn {
			border: none;
			border-radius: 10px;
			padding: 9px 13px;
			cursor: pointer;
			font-weight: 800;
			letter-spacing: 0.2px;
			font-size: 13px;
		}
		.approve { background: #047857; color: #f8fafc; }
		.deny { background: #991b1b; color: #f8fafc; }
		.empty {
			background: rgba(255,255,255,0.12);
			border: 1px solid rgba(255,255,255,0.2);
			border-radius: 14px;
			color: #e2e8f0;
			padding: 22px;
			text-align: center;
			font-weight: 700;
		}
	</style>
</head>
<body>
	<main>
		<section class="hero">
			<div>
				<h1>Faramesh Approvals Inbox</h1>
				<p class="sub">Resolve deferred actions with auditable approve/deny decisions.</p>
			</div>
			<div class="count">%d pending</div>
		</section>
`, pendingCount)

	if message != "" {
		className := "ok"
		if statusMsg == "error" {
			className = "err"
		}
		_, _ = fmt.Fprintf(w, "<div class=\"msg %s\">%s</div>", className, html.EscapeString(message))
	}

	if err != nil {
		_, _ = fmt.Fprintf(w, "<div class=\"msg err\">Failed to fetch pending approvals: %s</div>", html.EscapeString(err.Error()))
		_, _ = fmt.Fprint(w, "</main></body></html>")
		return
	}

	_, _ = fmt.Fprint(w, "<div class=\"toolbar\"><a class=\"refresh\" href=\"/approvals\">Refresh queue</a></div>")
	if len(items) == 0 {
		_, _ = fmt.Fprint(w, "<div class=\"empty\">No pending approvals. New deferred actions will appear here automatically.</div></main></body></html>")
		return
	}

	_, _ = fmt.Fprint(w, "<div class=\"grid\">")

	for _, item := range items {
		token := html.EscapeString(approvalTokenFromItem(item))
		agent := html.EscapeString(firstNonEmpty(item["agent_id"], "unknown-agent"))
		tool := html.EscapeString(firstNonEmpty(item["tool_id"], item["tool"], "unknown-tool"))
		reason := html.EscapeString(firstNonEmpty(item["reason"], item["message"], ""))

		_, _ = fmt.Fprint(w, "<section class=\"card\">")
		_, _ = fmt.Fprintf(w, "<div class=\"row\"><span class=\"pill\">agent %s</span><span class=\"pill\">tool %s</span></div>", agent, tool)
		_, _ = fmt.Fprintf(w, "<div class=\"kv\"><strong>Approval ID:</strong> %s</div>", token)
		if reason != "" {
			_, _ = fmt.Fprintf(w, "<div class=\"kv\"><strong>Context:</strong> %s</div>", reason)
		}
		_, _ = fmt.Fprint(w, "<form method=\"post\" action=\"/approvals/decision\">")
		_, _ = fmt.Fprintf(w, "<input type=\"hidden\" name=\"approval_id\" value=\"%s\">", token)
		_, _ = fmt.Fprint(w, "<input class=\"reason\" name=\"reason\" placeholder=\"Optional decision reason (stored in audit evidence)\">")
		_, _ = fmt.Fprint(w, "<div class=\"actions\"><button class=\"btn approve\" name=\"decision\" value=\"approve\" type=\"submit\">Approve</button><button class=\"btn deny\" name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></div></form></section>")
	}

	_, _ = fmt.Fprint(w, "</div></main></body></html>")
}

func handleApprovalsDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape("invalid form payload"), http.StatusFound)
		return
	}

	approvalID := strings.TrimSpace(r.FormValue("approval_id"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	decision := strings.ToLower(strings.TrimSpace(r.FormValue("decision")))
	approved := decision == "approve"
	if decision != "approve" && decision != "deny" {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape("decision must be approve or deny"), http.StatusFound)
		return
	}

	if err := submitApprovalsDecision(approvalID, approved, reason); err != nil {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	result := "approved"
	if !approved {
		result = "denied"
	}
	http.Redirect(w, r, "/approvals?status=ok&message="+url.QueryEscape("approval "+approvalID+" "+result), http.StatusFound)
}

func fetchPendingApprovals(agent string) ([]map[string]string, error) {
	socketReq := map[string]any{
		"type": "agent",
		"op":   "pending",
	}
	query := map[string]string{}
	if filter := strings.TrimSpace(agent); filter != "" {
		socketReq["agent"] = filter
		query["agent"] = filter
	}

	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), socketReq)
	if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
		raw, err = daemonGetWithQuery("/api/v1/agent/pending", query)
	}
	if err != nil {
		return nil, err
	}

	var payload struct {
		Items []map[string]string `json:"items"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode pending approvals: %w", err)
	}

	normalized := make([]map[string]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		row := map[string]string{}
		for k, v := range item {
			row[k] = v
		}
		token := approvalTokenFromItem(row)
		if token != "" {
			row["approval_id"] = token
			if strings.TrimSpace(row["id"]) == token {
				delete(row, "id")
			}
		}
		delete(row, "defer_token")
		delete(row, "approval_token")
		delete(row, "token")
		normalized = append(normalized, row)
	}

	return normalized, nil
}

func approvalTokenFromItem(item map[string]string) string {
	return strings.TrimSpace(firstNonEmpty(item["approval_id"], item["defer_token"], item["approval_token"], item["token"], item["id"]))
}

func requestDeferStatus(approvalID, agentHint string) (map[string]any, error) {
	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), map[string]any{
		"type":        "poll_defer",
		"defer_token": strings.TrimSpace(approvalID),
		"agent_id":    strings.TrimSpace(agentHint),
	})
	if err != nil {
		return map[string]any{"status": "unknown"}, err
	}

	status := map[string]any{}
	if err := json.Unmarshal(raw, &status); err != nil {
		return map[string]any{"status": "unknown"}, fmt.Errorf("decode approval status: %w", err)
	}
	return status, nil
}

func submitApprovalsDecision(approvalID string, approved bool, reason string) error {
	approvalID = strings.TrimSpace(approvalID)
	if approvalID == "" {
		return fmt.Errorf("approval ID is required")
	}

	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), map[string]any{
		"type":        "approve_defer",
		"defer_token": approvalID,
		"approved":    approved,
		"reason":      strings.TrimSpace(reason),
	})
	if err != nil {
		if daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonPost("/api/v1/agent/approve", map[string]any{
				"defer_token": approvalID,
				"approved":    approved,
				"reason":      strings.TrimSpace(reason),
			})
		}
		if err != nil {
			return err
		}
	}

	if len(raw) == 0 {
		return nil
	}

	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode approval response: %w", err)
	}
	if ok, _ := resp["ok"].(bool); ok {
		return nil
	}
	if emsg, _ := resp["error"].(string); strings.TrimSpace(emsg) != "" {
		return fmt.Errorf("%s", emsg)
	}
	return fmt.Errorf("approval decision request was rejected")
}

func normalizeApprovalsJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}

	normalized := normalizeApprovalValue(payload)
	out, err := json.Marshal(normalized)
	if err != nil {
		return raw
	}
	return out
}

func normalizeApprovalValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, nested := range typed {
			normalizedNested := normalizeApprovalValue(nested)
			switch key {
			case "defer_token", "approval_token":
				if _, exists := out["approval_id"]; !exists {
					out["approval_id"] = normalizedNested
				}
				continue
			case "token":
				if _, exists := out["approval_id"]; exists {
					continue
				}
				out["approval_id"] = normalizedNested
				continue
			default:
				out[key] = normalizedNested
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeApprovalValue(item))
		}
		return out
	default:
		return value
	}
}

func wrapApprovalsConnectivityError(err error) error {
	msg := strings.TrimSpace(err.Error())
	if strings.Contains(strings.ToLower(msg), "cannot reach daemon socket") || strings.Contains(strings.ToLower(msg), "connect:") {
		return fmt.Errorf("approvals runtime is not reachable. Start runtime with faramesh up --policy <policy> and retry")
	}
	return err
}

func printApprovalsQueue(title string, items []map[string]string, agentFilter string) {
	printHeader(title)
	if agentFilter != "" {
		printNoteLine("Filter: agent=" + agentFilter)
	}
	if len(items) == 0 {
		printReadyLine("No pending approvals")
		printNextStepLine("Watch queue: faramesh approvals watch")
		return
	}

	sort.SliceStable(items, func(i, j int) bool {
		return approvalTimestamp(items[i]).After(approvalTimestamp(items[j]))
	})

	printNoteLine(fmt.Sprintf("%d pending approval(s)", len(items)))
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "APPROVAL ID\tAGENT\tTOOL\tAGE\tCONTEXT")
	for _, item := range items {
		fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\n",
			approvalTokenFromItem(item),
			firstNonEmpty(strings.TrimSpace(item["agent_id"]), "-"),
			firstNonEmpty(strings.TrimSpace(item["tool_id"]), strings.TrimSpace(item["tool"]), "-"),
			approvalAge(item),
			truncateRunes(firstNonEmpty(strings.TrimSpace(item["reason"]), strings.TrimSpace(item["message"]), "-"), 54),
		)
	}
	_ = tw.Flush()
	fmt.Println()
	printNextStepLine("Inspect one: faramesh approvals show <approval-id>")
}

func printApprovalsWatchSnapshot(items []map[string]string, agentFilter string) {
	stamp := time.Now().Format(time.RFC3339)
	printHeader("Approval Queue Watch")
	printNoteLine("Updated: " + stamp)
	printApprovalsQueue("Live Approval Queue", items, agentFilter)
}

func printApprovalDetail(token, statusValue string, match map[string]string, statusErr error) {
	printHeader("Approval Detail")
	fmt.Printf("Approval ID: %s\n", token)
	fmt.Printf("Status:      %s\n", strings.ToUpper(firstNonEmpty(statusValue, "unknown")))

	if match != nil {
		agent := firstNonEmpty(strings.TrimSpace(match["agent_id"]), "-")
		tool := firstNonEmpty(strings.TrimSpace(match["tool_id"]), strings.TrimSpace(match["tool"]), "-")
		reason := firstNonEmpty(strings.TrimSpace(match["reason"]), strings.TrimSpace(match["message"]), "-")
		fmt.Printf("Agent:       %s\n", agent)
		fmt.Printf("Tool:        %s\n", tool)
		fmt.Printf("Requested:   %s ago\n", approvalAge(match))
		fmt.Printf("Context:     %s\n", reason)
	}

	if statusErr != nil {
		printWarningLine("status lookup warning: " + statusErr.Error())
	}

	if strings.EqualFold(statusValue, "pending") || match != nil {
		printNextStepLine("Approve: faramesh approvals approve " + token + " --reason \"approved\"")
		printNextStepLine("Deny: faramesh approvals deny " + token + " --reason \"denied\"")
		printNextStepLine("Explain: faramesh explain approval " + token)
	} else {
		printNextStepLine("Explain: faramesh explain approval " + token)
	}
}

func approvalTimestamp(item map[string]string) time.Time {
	for _, key := range []string{"created_at", "requested_at", "updated_at", "timestamp", "ts"} {
		if raw := strings.TrimSpace(item[key]); raw != "" {
			if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				return t
			}
			if t, err := time.Parse(time.RFC3339, raw); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

func approvalAge(item map[string]string) string {
	t := approvalTimestamp(item)
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	if max == 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

func httpEndpointHealthy(url string) bool {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
