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
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	approvalsCmd = &cobra.Command{
		Use:   "approvals",
		Short: "Manage pending governance approvals",
		Long:  "List pending deferred actions, resolve approvals, and open the approvals UI.",
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

	approvalsApproveCmd = &cobra.Command{
		Use:   "approve <defer-token>",
		Short: "Approve a pending deferred action",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return sendApproval(args[0], true, strings.TrimSpace(approvalsReason))
		},
	}

	approvalsDenyCmd = &cobra.Command{
		Use:   "deny <defer-token>",
		Short: "Deny a pending deferred action",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return sendApproval(args[0], false, strings.TrimSpace(approvalsReason))
		},
	}

	approvalsUICmd = &cobra.Command{
		Use:   "ui",
		Short: "Show or open the approvals UI",
		Args:  cobra.NoArgs,
		RunE:  runApprovalsUI,
	}

	approvalsAgentFilter   string
	approvalsReason        string
	approvalsUIURL         string
	approvalsUIOpen        bool
	approvalsUIRequireLive bool
	approvalsUIBind        string
)

func init() {
	approvalsListCmd.Flags().StringVar(&approvalsAgentFilter, "agent", "", "filter by agent ID")
	approvalsApproveCmd.Flags().StringVar(&approvalsReason, "reason", "", "approval reason")
	approvalsDenyCmd.Flags().StringVar(&approvalsReason, "reason", "", "denial reason")
	approvalsUICmd.Flags().StringVar(&approvalsUIURL, "url", "", "approvals UI URL override")
	approvalsUICmd.Flags().BoolVar(&approvalsUIOpen, "open", false, "open approvals UI in default browser")
	approvalsUICmd.Flags().BoolVar(&approvalsUIRequireLive, "require-live", false, "fail if approvals UI endpoint is unreachable")
	approvalsUICmd.Flags().StringVar(&approvalsUIBind, "bind", "127.0.0.1:39090", "bind address for built-in approvals UI fallback server")

	approvalsCmd.AddCommand(approvalsListCmd)
	approvalsCmd.AddCommand(approvalsPendingCmd)
	approvalsCmd.AddCommand(approvalsApproveCmd)
	approvalsCmd.AddCommand(approvalsDenyCmd)
	approvalsCmd.AddCommand(approvalsUICmd)

	rootCmd.AddCommand(approvalsCmd)
}

func runApprovalsList(_ *cobra.Command, _ []string) error {
	socketReq := map[string]any{
		"type": "agent",
		"op":   "pending",
	}
	query := map[string]string{}
	if filter := strings.TrimSpace(approvalsAgentFilter); filter != "" {
		socketReq["agent"] = filter
		query["agent"] = filter
	}

	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), socketReq)
	if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
		raw, err = daemonGetWithQuery("/api/v1/agent/pending", query)
	}
	if err != nil {
		return err
	}
	printResponse("Pending Approvals", raw)
	return nil
}

func runApprovalsUI(_ *cobra.Command, _ []string) error {
	targetURL, err := resolveApprovalsURL(approvalsUIURL)
	if err != nil {
		return err
	}

	if targetURL != "" && httpEndpointHealthy(targetURL) {
		fmt.Printf("approvals UI: %s\n", targetURL)
		if approvalsUIOpen {
			if err := openBrowserURL(targetURL); err != nil {
				return err
			}
		}
		return nil
	}

	if targetURL != "" && approvalsUIRequireLive {
		return fmt.Errorf("approvals UI is not reachable at %s", targetURL)
	}

	builtInURL, serveErr := serveEmbeddedApprovalsUI(strings.TrimSpace(approvalsUIBind), approvalsUIOpen)
	if serveErr != nil {
		if targetURL != "" {
			return fmt.Errorf("dashboard approvals UI unavailable (%s) and built-in fallback failed: %w", targetURL, serveErr)
		}
		return fmt.Errorf("built-in approvals UI fallback failed: %w", serveErr)
	}

	fmt.Printf("approvals UI: %s\n", builtInURL)
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

	fmt.Printf("built-in approvals UI fallback server listening on %s (Ctrl+C to stop)\n", httpURL)
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

	_, _ = fmt.Fprint(w, "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Faramesh Approvals</title><style>body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f6f7fb;color:#111827;margin:0}main{max-width:960px;margin:0 auto;padding:24px}h1{margin:0 0 8px 0}p.sub{margin:0 0 20px 0;color:#4b5563}.msg{padding:10px 12px;border-radius:8px;margin-bottom:16px}.ok{background:#ecfdf5;color:#065f46;border:1px solid #a7f3d0}.err{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}.card{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin-bottom:12px}.row{display:flex;gap:12px;flex-wrap:wrap}.pill{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:999px;padding:2px 10px;font-size:12px}.kv{color:#374151;font-size:14px;margin:6px 0}form{margin-top:12px}.reason{width:100%;padding:8px;border:1px solid #d1d5db;border-radius:8px}.actions{display:flex;gap:8px;margin-top:8px}.btn{border:none;border-radius:8px;padding:8px 12px;cursor:pointer;font-weight:600}.approve{background:#065f46;color:white}.deny{background:#991b1b;color:white}.refresh{background:#111827;color:white;text-decoration:none;display:inline-block;margin-bottom:16px;padding:8px 12px;border-radius:8px}</style></head><body><main><h1>Faramesh Approvals</h1><p class=\"sub\">Built-in fallback UI for pending governance decisions.</p>")

	if message != "" {
		className := "ok"
		if statusMsg == "error" {
			className = "err"
		}
		_, _ = fmt.Fprintf(w, "<div class=\"msg %s\">%s</div>", className, html.EscapeString(message))
	}

	if err != nil {
		_, _ = fmt.Fprintf(w, "<div class=\"msg err\">failed to fetch pending approvals: %s</div>", html.EscapeString(err.Error()))
		_, _ = fmt.Fprint(w, "</main></body></html>")
		return
	}

	_, _ = fmt.Fprint(w, "<a class=\"refresh\" href=\"/approvals\">Refresh</a>")
	if len(items) == 0 {
		_, _ = fmt.Fprint(w, "<div class=\"card\"><strong>No pending approvals.</strong></div></main></body></html>")
		return
	}

	for _, item := range items {
		token := html.EscapeString(strings.TrimSpace(item["defer_token"]))
		agent := html.EscapeString(firstNonEmpty(item["agent_id"], "unknown-agent"))
		tool := html.EscapeString(firstNonEmpty(item["tool_id"], item["tool"], "unknown-tool"))
		reason := html.EscapeString(firstNonEmpty(item["reason"], item["message"], ""))

		_, _ = fmt.Fprint(w, "<section class=\"card\">")
		_, _ = fmt.Fprintf(w, "<div class=\"row\"><span class=\"pill\">agent %s</span><span class=\"pill\">tool %s</span></div>", agent, tool)
		_, _ = fmt.Fprintf(w, "<div class=\"kv\"><strong>defer token:</strong> %s</div>", token)
		if reason != "" {
			_, _ = fmt.Fprintf(w, "<div class=\"kv\"><strong>context:</strong> %s</div>", reason)
		}
		_, _ = fmt.Fprint(w, "<form method=\"post\" action=\"/approvals/decision\">")
		_, _ = fmt.Fprintf(w, "<input type=\"hidden\" name=\"defer_token\" value=\"%s\">", token)
		_, _ = fmt.Fprint(w, "<input class=\"reason\" name=\"reason\" placeholder=\"optional decision reason\">")
		_, _ = fmt.Fprint(w, "<div class=\"actions\"><button class=\"btn approve\" name=\"decision\" value=\"approve\" type=\"submit\">Approve</button><button class=\"btn deny\" name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></div></form></section>")
	}

	_, _ = fmt.Fprint(w, "</main></body></html>")
}

func handleApprovalsDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape("invalid form payload"), http.StatusFound)
		return
	}

	token := strings.TrimSpace(r.FormValue("defer_token"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	decision := strings.ToLower(strings.TrimSpace(r.FormValue("decision")))
	approved := decision == "approve"
	if decision != "approve" && decision != "deny" {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape("decision must be approve or deny"), http.StatusFound)
		return
	}

	if err := submitApprovalsDecision(token, approved, reason); err != nil {
		http.Redirect(w, r, "/approvals?status=error&message="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	result := "approved"
	if !approved {
		result = "denied"
	}
	http.Redirect(w, r, "/approvals?status=ok&message="+url.QueryEscape("token "+token+" "+result), http.StatusFound)
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

	return payload.Items, nil
}

func submitApprovalsDecision(token string, approved bool, reason string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("defer token is required")
	}

	raw, err := daemonSocketRequestAt(resolveApprovalsSocketPath(), map[string]any{
		"type":        "approve_defer",
		"defer_token": token,
		"approved":    approved,
		"reason":      strings.TrimSpace(reason),
	})
	if err != nil {
		if daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonPost("/api/v1/agent/approve", map[string]any{
				"defer_token": token,
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
	return fmt.Errorf("approval request was rejected")
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
