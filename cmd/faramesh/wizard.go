package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	wizardCmd = &cobra.Command{
		Use:   "wizard",
		Short: "Guided onboarding and first-run workflows",
		Long:  "Intent-first guided onboarding for credential sequestration, runtime startup, approvals, and governed execution.",
		Args:  cobra.NoArgs,
		RunE:  runWizardFirstRun,
	}

	wizardFirstRunCmd = &cobra.Command{
		Use:   "first-run",
		Short: "Launch guided first-run setup",
		Args:  cobra.NoArgs,
		RunE:  runWizardFirstRun,
	}

	wizardProfileCmd = &cobra.Command{
		Use:   "profile",
		Short: "Show wizard-relevant runtime and credential profile state",
		Args:  cobra.NoArgs,
		RunE:  runWizardProfile,
	}

	wizardPolicyPath        string
	wizardEnvironment       string
	wizardMode              string
	wizardCredentialMode    string
	wizardCredentialBackend string
	wizardProviderKeys      []string
	wizardImportEnv         bool
	wizardRunNowMode        string
	wizardAgentExec         string
	wizardAgentArgs         []string
	wizardAgentCmd          string
	wizardOpenApprovals     bool
	wizardYes               bool
)

func init() {
	wizardFirstRunCmd.Flags().StringVar(&wizardPolicyPath, "policy", "", "policy path (auto-detected or bootstrapped if omitted)")
	wizardFirstRunCmd.Flags().StringVar(&wizardEnvironment, "environment", "auto", "environment profile: auto|local-agent|service|advanced")
	wizardFirstRunCmd.Flags().StringVar(&wizardCredentialMode, "credential-sequestration", "auto", "configure credential sequestration during setup: auto|yes|no")
	wizardFirstRunCmd.Flags().StringVar(&wizardRunNowMode, "run-now", "auto", "run one governed command during setup: auto|yes|no")
	wizardFirstRunCmd.Flags().StringVar(&wizardAgentExec, "agent-exec", "", "executable for optional immediate governed run (for example: python)")
	wizardFirstRunCmd.Flags().StringArrayVar(&wizardAgentArgs, "agent-arg", nil, "argument for optional immediate governed run (repeatable)")
	wizardFirstRunCmd.Flags().BoolVar(&wizardOpenApprovals, "open-approvals", false, "open approvals UI after runtime starts")
	wizardFirstRunCmd.Flags().BoolVar(&wizardYes, "yes", false, "non-interactive mode; accept recommended defaults")

	// Advanced compatibility flags remain available but hidden from default first-run UX.
	wizardFirstRunCmd.Flags().StringVar(&wizardMode, "mode", "", "advanced: governance mode override (enforce|shadow|audit)")
	wizardFirstRunCmd.Flags().StringVar(&wizardCredentialBackend, "credential-backend", "local-vault", "advanced: credential backend local-vault|vault|env")
	wizardFirstRunCmd.Flags().StringArrayVar(&wizardProviderKeys, "provider-key", nil, "advanced: provider credential mapping provider=value (repeatable)")
	wizardFirstRunCmd.Flags().BoolVar(&wizardImportEnv, "import-env", true, "advanced: import known provider keys from environment")
	wizardFirstRunCmd.Flags().StringVar(&wizardAgentCmd, "agent-cmd", "", "advanced legacy command string for immediate governed run")
	_ = wizardFirstRunCmd.Flags().MarkHidden("mode")
	_ = wizardFirstRunCmd.Flags().MarkHidden("credential-backend")
	_ = wizardFirstRunCmd.Flags().MarkHidden("provider-key")
	_ = wizardFirstRunCmd.Flags().MarkHidden("import-env")
	_ = wizardFirstRunCmd.Flags().MarkHidden("agent-cmd")

	wizardCmd.AddCommand(wizardFirstRunCmd)
	wizardCmd.AddCommand(wizardProfileCmd)
	rootCmd.AddCommand(wizardCmd)
}

func runWizardFirstRun(_ *cobra.Command, _ []string) error {
	printHeader("Faramesh First-Run Wizard")
	printNoteLine("This guided flow configures Faramesh by intent: policy, credential sequestration, runtime startup, and approvals.")

	environment, err := resolveWizardEnvironment(wizardEnvironment, wizardYes)
	if err != nil {
		return err
	}

	mode, err := resolveWizardGovernanceMode(environment, wizardMode, wizardYes)
	if err != nil {
		return err
	}

	policyPath, err := resolveWizardPolicyPath(wizardPolicyPath)
	if err != nil {
		return err
	}
	printNoteLine("Environment profile: " + environment)
	printSuccessLine("Policy ready: " + policyPath)

	setupCredentials, err := resolveMode(wizardCredentialMode, wizardYes, "Enable credential sequestration defaults now?")
	if err != nil {
		return err
	}
	if setupCredentials {
		printNoteLine("Step 1/3: Configure credential sequestration defaults")
		args := []string{
			"credential", "enable",
			"--policy", policyPath,
			"--apply-runtime=false",
		}
		if environment == "advanced" {
			args = append(args,
				"--backend", wizardCredentialBackend,
				"--import-env="+strings.ToLower(fmt.Sprintf("%t", wizardImportEnv)),
			)
			for _, item := range wizardProviderKeys {
				args = append(args, "--provider-key", item)
			}
		}
		if err := runFaramesh(args...); err != nil {
			return err
		}
	} else {
		printWarningLine("Credential sequestration setup was skipped")
		printTipLine("Run later: faramesh credential enable --policy " + policyPath)
	}

	printNoteLine("Step 2/3: Start runtime")
	upArgs := []string{"up", "--policy", policyPath, "--mode", mode}
	if wizardOpenApprovals {
		upArgs = append(upArgs, "--open-approvals")
	}
	if err := runFaramesh(upArgs...); err != nil {
		return err
	}

	runNow, err := resolveMode(wizardRunNowMode, wizardYes, "Run one governed agent command now?")
	if err != nil {
		return err
	}
	if runNow {
		printNoteLine("Step 3/3: Optional first governed run")
		agentExec, agentArgs, err := resolveWizardAgentCommand(environment, wizardAgentExec, wizardAgentArgs, wizardAgentCmd, wizardYes)
		if err != nil {
			return err
		}
		if agentExec != "" {
			printNoteLine("Running governed command now")
			runArgs := []string{"run", "--broker", "--policy", policyPath, "--", agentExec}
			runArgs = append(runArgs, agentArgs...)
			if err := runFaramesh(runArgs...); err != nil {
				return err
			}
		} else {
			printWarningLine("Run-now is enabled, but no executable was provided")
		}
	}

	printReadyLine("First-run setup completed")
	printNextStepLine("Review pending actions: faramesh approvals")
	printNextStepLine("Explain a decision: faramesh explain <action-id>")
	printNextStepLine("Stream live evidence: faramesh audit tail")
	printNextStepLine("Verify audit integrity: faramesh audit verify")
	return nil
}

func resolveWizardEnvironment(raw string, assumeYes bool) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "local-agent", "local", "agent":
		return "local-agent", nil
	case "service":
		return "service", nil
	case "advanced":
		return "advanced", nil
	case "", "auto":
		if assumeYes {
			return "local-agent", nil
		}
		return promptWizardChoice("Choose your environment profile", []string{"local-agent", "service", "advanced"}, "local-agent")
	default:
		return "", fmt.Errorf("invalid --environment %q (expected auto|local-agent|service|advanced)", raw)
	}
}

func resolveWizardGovernanceMode(environment, rawMode string, assumeYes bool) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(rawMode))
	if mode != "" {
		if mode != "enforce" && mode != "shadow" && mode != "audit" {
			return "", fmt.Errorf("invalid --mode %q (expected enforce|shadow|audit)", rawMode)
		}
		return mode, nil
	}

	if environment != "advanced" {
		return "enforce", nil
	}
	if assumeYes {
		return "enforce", nil
	}
	return promptWizardChoice("Choose governance mode", []string{"enforce", "shadow", "audit"}, "enforce")
}

func resolveWizardAgentCommand(environment, execFlag string, argsFlag []string, legacyCmd string, assumeYes bool) (string, []string, error) {
	if execValue := strings.TrimSpace(execFlag); execValue != "" {
		cleanArgs := make([]string, 0, len(argsFlag))
		for _, arg := range argsFlag {
			trimmed := strings.TrimSpace(arg)
			if trimmed != "" {
				cleanArgs = append(cleanArgs, trimmed)
			}
		}
		return execValue, cleanArgs, nil
	}

	if legacy := strings.TrimSpace(legacyCmd); legacy != "" {
		parts := strings.Fields(legacy)
		if len(parts) == 0 {
			return "", nil, nil
		}
		return parts[0], parts[1:], nil
	}

	if assumeYes {
		return "", nil, nil
	}

	defaultExec := "python"
	if environment == "service" {
		defaultExec = "node"
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Executable for first governed run [%s]: ", defaultExec)
	execLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", nil, err
	}
	execValue := strings.TrimSpace(execLine)
	if execValue == "" {
		execValue = defaultExec
	}

	fmt.Print("Arguments (optional, space-separated): ")
	argsLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", nil, err
	}
	args := strings.Fields(strings.TrimSpace(argsLine))
	return execValue, args, nil
}

func promptWizardChoice(prompt string, choices []string, defaultChoice string) (string, error) {
	if len(choices) == 0 {
		return "", fmt.Errorf("wizard choice requires options")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	for idx, choice := range choices {
		fmt.Printf("  %d) %s\n", idx+1, choice)
	}
	fmt.Printf("Choose [%s]: ", defaultChoice)
	input, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return defaultChoice, nil
	}

	for _, choice := range choices {
		if input == strings.ToLower(choice) {
			return choice, nil
		}
	}

	for idx, choice := range choices {
		if input == fmt.Sprintf("%d", idx+1) {
			return choice, nil
		}
	}

	return "", fmt.Errorf("invalid selection %q", input)
}

func resolveWizardPolicyPath(raw string) (string, error) {
	explicit := strings.TrimSpace(raw)
	if explicit != "" {
		if abs, err := filepath.Abs(explicit); err == nil {
			return abs, nil
		}
		return explicit, nil
	}

	if state, ok := readCurrentRuntimeStartState(); ok {
		if policyPath := strings.TrimSpace(state.PolicyPath); policyPath != "" {
			return policyPath, nil
		}
	}

	if detected := strings.TrimSpace(detectDefaultPolicyPath()); detected != "" {
		return detected, nil
	}

	stateDir, err := resolveRuntimeStateDir("")
	if err != nil {
		return "", err
	}
	generated, _, err := ensureBootstrapPolicy(stateDir)
	if err != nil {
		return "", err
	}
	return generated, nil
}

func runWizardProfile(_ *cobra.Command, _ []string) error {
	payload := map[string]any{}
	if state, ok := readCurrentRuntimeStartState(); ok {
		payload["runtime"] = state
	}
	if profile, err := loadRuntimeProfile(); err == nil {
		payload["profile"] = profile
	}
	if len(payload) == 0 {
		printNoteLine("No wizard profile state found")
		printNextStepLine("Run: faramesh wizard first-run")
		return nil
	}
	body, _ := json.Marshal(payload)
	printHeader("Wizard Profile")
	printJSON(body)
	return nil
}
