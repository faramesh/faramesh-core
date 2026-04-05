package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func modelSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string) (json.RawMessage, error) {
	req := map[string]any{"type": "model", "op": op}
	for k, v := range payload {
		req[k] = v
	}
	resp, err := daemonSocketRequest(req)
	if err == nil {
		return resp, nil
	}
	if !daemonHTTPFallback {
		return nil, err
	}
	if httpMethod == "GET" {
		if len(payload) == 0 {
			return daemonGet(httpPath)
		}
		q := map[string]string{}
		for k, v := range payload {
			if s, ok := v.(string); ok {
				q[k] = s
			}
		}
		return daemonGetWithQuery(httpPath, q)
	}
	return daemonPost(httpPath, payload)
}

var modelCmd = &cobra.Command{
	Use:   "model",
	Short: "Model identity registration, verification, and consistency checks",
}

var (
	modelRegFingerprint string
	modelRegProvider    string
	modelRegVersion     string
)

var modelRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a model identity with the governance daemon",
	Args:  cobra.ExactArgs(1),
	RunE:  runModelRegister,
}

var modelVerifyAgent string

var modelVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the model identity bound to an agent",
	Args:  cobra.NoArgs,
	RunE:  runModelVerify,
}

var (
	modelConsistAgent  string
	modelConsistWindow string
)

var modelConsistencyCmd = &cobra.Command{
	Use:   "consistency",
	Short: "Check model consistency for an agent over a time window",
	Args:  cobra.NoArgs,
	RunE:  runModelConsistency,
}

var modelListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered models",
	Args:  cobra.NoArgs,
	RunE:  runModelList,
}

var modelAlertCmd = &cobra.Command{
	Use:   "alert <agent-id>",
	Short: "Show model identity alerts for an agent",
	Args:  cobra.ExactArgs(1),
	RunE:  runModelAlert,
}

func init() {
	modelRegisterCmd.Flags().StringVar(&modelRegFingerprint, "fingerprint", "", "model fingerprint hash")
	modelRegisterCmd.Flags().StringVar(&modelRegProvider, "provider", "", "model provider (e.g. openai, anthropic)")
	modelRegisterCmd.Flags().StringVar(&modelRegVersion, "version", "", "model version identifier")

	modelVerifyCmd.Flags().StringVar(&modelVerifyAgent, "agent", "", "agent identifier to verify")

	modelConsistencyCmd.Flags().StringVar(&modelConsistAgent, "agent", "", "agent identifier")
	modelConsistencyCmd.Flags().StringVar(&modelConsistWindow, "window", "24h", "time window for consistency check")

	modelCmd.AddCommand(modelRegisterCmd, modelVerifyCmd, modelConsistencyCmd, modelListCmd, modelAlertCmd)
	rootCmd.AddCommand(modelCmd)
}

func runModelRegister(_ *cobra.Command, args []string) error {
	payload := map[string]any{
		"name":        args[0],
		"fingerprint": modelRegFingerprint,
		"provider":    modelRegProvider,
		"version":     modelRegVersion,
	}
	resp, err := modelSocketRequestWithHTTPFallback("register", payload, "POST", "/api/v1/model/register")
	if err != nil {
		return err
	}
	printResponse("Model Registered", resp)
	return nil
}

func runModelVerify(_ *cobra.Command, _ []string) error {
	body := map[string]any{}
	if modelVerifyAgent != "" {
		body["agent"] = modelVerifyAgent
	}
	resp, err := modelSocketRequestWithHTTPFallback("verify", body, "POST", "/api/v1/model/verify")
	if err != nil {
		return err
	}
	printResponse("Model Verification", resp)
	return nil
}

func runModelConsistency(_ *cobra.Command, _ []string) error {
	body := map[string]any{
		"window": modelConsistWindow,
	}
	if modelConsistAgent != "" {
		body["agent"] = modelConsistAgent
	}
	resp, err := modelSocketRequestWithHTTPFallback("consistency", body, "POST", "/api/v1/model/consistency")
	if err != nil {
		return err
	}
	printResponse("Model Consistency", resp)
	return nil
}

func runModelList(_ *cobra.Command, _ []string) error {
	resp, err := modelSocketRequestWithHTTPFallback("list", map[string]any{}, "GET", "/api/v1/model/list")
	if err != nil {
		return err
	}
	printResponse("Registered Models", resp)
	return nil
}

func runModelAlert(_ *cobra.Command, args []string) error {
	resp, err := modelSocketRequestWithHTTPFallback("alert", map[string]any{"agent": args[0]}, "GET", "/api/v1/model/alert")
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Model Alerts — %s", args[0]), resp)
	return nil
}
