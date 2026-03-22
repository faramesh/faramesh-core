package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	daemonAddr       string
	daemonHTTPClient = &http.Client{Timeout: 30 * time.Second}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&daemonAddr, "addr", "http://localhost:7777", "daemon HTTP address")
}

func daemonURL(path string) string {
	addr := strings.TrimRight(daemonAddr, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return addr + path
}

func daemonPost(path string, payload any) (json.RawMessage, error) {
	var reqBody io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	resp, err := daemonHTTPClient.Post(daemonURL(path), "application/json", reqBody)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", daemonAddr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func daemonGet(path string) (json.RawMessage, error) {
	resp, err := daemonHTTPClient.Get(daemonURL(path))
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", daemonAddr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func daemonGetWithQuery(path string, query map[string]string) (json.RawMessage, error) {
	u := daemonURL(path)
	if len(query) > 0 {
		params := url.Values{}
		for k, v := range query {
			if v != "" {
				params.Set(k, v)
			}
		}
		if encoded := params.Encode(); encoded != "" {
			u += "?" + encoded
		}
	}
	resp, err := daemonHTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", daemonAddr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func readDaemonResponse(resp *http.Response) (json.RawMessage, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("daemon returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	return json.RawMessage(raw), nil
}

var headerColor = color.New(color.Bold, color.FgCyan)

func printHeader(header string) {
	headerColor.Fprintf(os.Stdout, "\n%s\n", header)
	fmt.Fprintln(os.Stdout, strings.Repeat("─", len(header)))
}

func printJSON(data json.RawMessage) {
	if len(data) == 0 {
		color.New(color.FgGreen).Fprintln(os.Stdout, "  OK")
		fmt.Println()
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "  ", "  "); err != nil {
		fmt.Fprintf(os.Stdout, "  %s\n\n", strings.TrimSpace(string(data)))
		return
	}
	fmt.Fprintf(os.Stdout, "  %s\n\n", pretty.String())
}

func printResponse(header string, raw json.RawMessage) {
	printHeader(header)
	printJSON(raw)
}
