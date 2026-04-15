package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/hub"
)

var hubCmd = &cobra.Command{
	Use:   "hub",
	Short: "Manage policy pack registry operations",
	Long: `Install, search, publish, and verify signed policy packs from a registry
using --hub-url / FARAMESH_HUB_URL. Compatible with self-hosted or future Hub backends;
this binary only ships the client.`,
}

var (
	hubURL                      string
	hubToken                    string
	hubOrgID                    string
	hubSearchVisibility         string
	hubJSON                     bool
	hubInstallRoot              string
	hubQuarantineRoot           string
	hubAdmissionMode            string
	hubRequireSig               bool
	hubRequireVerifiedPublisher bool
	hubDisableReason            string
	hubPublishName              string
	hubPublishVersion           string
	hubTrust                    string
	packInstallMode             string
)

func init() {
	hubCmd.PersistentFlags().StringVar(&hubURL, "hub-url", "", "registry base URL (or FARAMESH_HUB_URL)")
	hubCmd.PersistentFlags().StringVar(&hubToken, "hub-token", "", "Bearer token for publish (or FARAMESH_HUB_TOKEN)")
	hubCmd.PersistentFlags().StringVar(&hubOrgID, "org-id", "", "org id for private catalog scope (or FARAMESH_HUB_ORG; sent as X-Faramesh-Org-Id)")
	hubCmd.PersistentFlags().BoolVar(&hubJSON, "json", false, "machine-readable JSON output")

	hubInstallCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	hubInstallCmd.Flags().StringVar(&hubQuarantineRoot, "quarantine-root", "", "quarantine root for rejected packs (default: ~/.faramesh/hub/quarantine)")
	hubInstallCmd.Flags().StringVar(&hubAdmissionMode, "admission-mode", "enforce", "install admission mode: off|warn|enforce")
	hubInstallCmd.Flags().StringVar(&hubDisableReason, "disable-reason", "install admission failed", "reason recorded when a pack is disabled by admission")
	hubInstallCmd.Flags().StringVar(&hubTrust, "trust", "verified", "trust tier acknowledgment: verified|community (community packs require explicit opt-in)")
	hubInstallCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned or signature invalid")
	hubInstallCmd.Flags().BoolVar(&hubRequireVerifiedPublisher, "require-verified-publisher", false, "reject packs without a registry-verified publisher identity")

	hubDisableCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	hubDisableCmd.Flags().StringVar(&hubDisableReason, "reason", "manually disabled", "reason recorded in the disable manifest")
	hubEnableCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	hubStatusCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")

	hubVerifyCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned")
	hubVerifyCmd.Flags().BoolVar(&hubRequireVerifiedPublisher, "require-verified-publisher", false, "fail if publisher is missing or not verified")

	hubSearchCmd.Flags().StringVar(&hubSearchVisibility, "visibility", "", "catalog filter: public|org|all (registry-supported; default server behavior when empty)")

	hubPublishCmd.Flags().StringVar(&hubPublishName, "name", "", "pack name (e.g. org/pack)")
	hubPublishCmd.Flags().StringVar(&hubPublishVersion, "version", "", "semver (e.g. 1.0.0)")
	_ = hubPublishCmd.MarkFlagRequired("name")
	_ = hubPublishCmd.MarkFlagRequired("version")

	hubCmd.AddCommand(hubSearchCmd)
	hubCmd.AddCommand(hubInstallCmd)
	hubCmd.AddCommand(hubDisableCmd)
	hubCmd.AddCommand(hubEnableCmd)
	hubCmd.AddCommand(hubStatusCmd)
	hubCmd.AddCommand(hubPublishCmd)
	hubCmd.AddCommand(hubVerifyCmd)
	rootCmd.AddCommand(hubCmd)
}

func hubClient() (*hub.Client, error) {
	u := strings.TrimSpace(hubURL)
	if u == "" {
		u = strings.TrimSpace(os.Getenv("FARAMESH_HUB_URL"))
	}
	c, err := hub.NewClient(u)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(hubToken)
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("FARAMESH_HUB_TOKEN"))
	}
	c.AuthBearer = tok
	org := strings.TrimSpace(hubOrgID)
	if org == "" {
		org = strings.TrimSpace(os.Getenv("FARAMESH_HUB_ORG"))
	}
	c.OrgID = org
	return c, nil
}

func hubInstallRootPath() (string, error) {
	if strings.TrimSpace(hubInstallRoot) != "" {
		return hubInstallRoot, nil
	}
	return hub.DefaultInstallRoot()
}

var hubSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search Hub for policy packs",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		query := args[0]
		c, err := hubClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var searchOpts *hub.SearchOptions
		if v := strings.TrimSpace(hubSearchVisibility); v != "" {
			searchOpts = &hub.SearchOptions{Visibility: v}
		}
		sr, err := c.Search(ctx, query, searchOpts)
		if err != nil {
			return err
		}
		if hubJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(sr)
		}
		bold := color.New(color.Bold)
		bold.Printf("Searching Hub for: %s\n", query)
		fmt.Println()
		fmt.Printf("%-40s %-12s %-12s %s\n", "PACK", "VERSION", "DOWNLOADS", "DESCRIPTION")
		fmt.Printf("%-40s %-12s %-12s %s\n", strings.Repeat("─", 40), strings.Repeat("─", 12), strings.Repeat("─", 12), strings.Repeat("─", 24))
		for _, p := range sr.Packs {
			desc := p.Description
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}
			fmt.Printf("%-40s %-12s %-12d %s\n", p.Name, p.LatestVersion, p.Downloads, desc)
		}
		if len(sr.Packs) == 0 {
			color.Yellow("No packs matched (empty registry response).")
		}
		return nil
	},
}

var hubInstallCmd = &cobra.Command{
	Use:   "install [pack-ref]",
	Short: "Install a policy pack from Hub",
	Long: `Install a policy pack. Reference format: org/pack or org/pack@version.
If version is omitted, "latest" is requested from the registry.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ref := args[0]
		name, ver, err := hub.ParsePackRef(ref)
		if err != nil {
			return err
		}
		pv, err := resolvePackVersion(name, ver)
		if err != nil {
			return err
		}
		if strings.EqualFold(strings.TrimSpace(pv.TrustTier), "community") &&
			!strings.EqualFold(strings.TrimSpace(hubTrust), "community") {
			return fmt.Errorf("pack trust_tier is community; re-run with --trust community to acknowledge")
		}
		if hubRequireSig && pv.Signature == nil {
			return fmt.Errorf("pack is unsigned (--require-signature)")
		}
		if err := hub.ValidatePackPayload(pv); err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		switch normalizePackInstallMode(packInstallMode) {
		case "shadow", "enforce":
		default:
			return fmt.Errorf("invalid install mode %q (supported: shadow|enforce)", packInstallMode)
		}
		admissionMode := strings.ToLower(strings.TrimSpace(hubAdmissionMode))
		switch admissionMode {
		case "", "enforce", "warn", "off":
			if admissionMode == "" {
				admissionMode = "enforce"
			}
		default:
			return fmt.Errorf("invalid admission mode %q (supported: off|warn|enforce)", hubAdmissionMode)
		}
		if admissionMode != "off" {
			admission := hub.EvaluateInstallAdmission(pv)
			if !admission.Allowed {
				disableReason := strings.TrimSpace(hubDisableReason)
				if disableReason == "" {
					disableReason = "install admission failed"
				}
				quarantineRoot := strings.TrimSpace(hubQuarantineRoot)
				if quarantineRoot == "" {
					quarantineRoot = filepath.Join(filepath.Dir(root), "quarantine")
				}
				qPath, qErr := hub.QuarantinePack(quarantineRoot, pv, "install admission failed", admission.Findings)
				if qErr != nil {
					return qErr
				}
				if admissionMode == "enforce" {
					if _, disableErr := hub.DisableInstalledPack(root, pv.Name, pv.Version, disableReason, admission.Findings); disableErr != nil && !errors.Is(disableErr, hub.ErrPackNotInstalled) {
						return disableErr
					}
					return fmt.Errorf("pack quarantined by install admission: %s", qPath)
				}
				if !hubJSON {
					color.Yellow("warning: pack failed admission checks and was quarantined at %s", qPath)
				}
				policyPath, err := hub.WritePackToDiskWithMode(root, pv, packInstallMode)
				if err != nil {
					return err
				}
				warnCompiled := filepath.Join(filepath.Dir(policyPath), "policy.compiled.yaml")
				warnCompiledBytes, warnReadErr := os.ReadFile(warnCompiled)
				dPath, disableErr := hub.DisableInstalledPack(root, pv.Name, pv.Version, disableReason, admission.Findings)
				if disableErr != nil {
					return disableErr
				}
				if hubJSON {
					m := map[string]any{
						"policy_path":       policyPath,
						"name":              pv.Name,
						"version":           pv.Version,
						"sha256_hex":        hub.Sum256Hex([]byte(pv.PolicyYAML)),
						"disabled":          true,
						"disabled_path":     dPath,
						"quarantine_path":   qPath,
						"admission_allowed": false,
						"applied_mode":      normalizePackInstallMode(packInstallMode),
					}
					if warnReadErr == nil {
						m["compiled_policy_path"] = warnCompiled
						m["policy_compiled_sha256"] = hub.Sum256Hex(warnCompiledBytes)
					}
					return json.NewEncoder(os.Stdout).Encode(m)
				}
				fmt.Printf("Installed %s@%s in disabled state\n", pv.Name, pv.Version)
				fmt.Printf("Policy written: %s\n", policyPath)
				if warnReadErr == nil {
					fmt.Printf("Compiled policy: %s\n", warnCompiled)
				}
				fmt.Printf("Disabled manifest: %s\n", dPath)
				fmt.Printf("Quarantine path: %s\n", qPath)
				return nil
			}
		}
		path, err := hub.WritePackToDiskWithMode(root, pv, packInstallMode)
		if err != nil {
			return err
		}
		compiledPath := filepath.Join(filepath.Dir(path), "policy.compiled.yaml")
		compiledBytes, err := os.ReadFile(compiledPath)
		if err != nil {
			return err
		}
		applied := normalizePackInstallMode(packInstallMode)
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"policy_path":            path,
				"compiled_policy_path":   compiledPath,
				"name":                   pv.Name,
				"version":                pv.Version,
				"sha256_hex":             hub.Sum256Hex([]byte(pv.PolicyYAML)),
				"policy_compiled_sha256": hub.Sum256Hex(compiledBytes),
				"applied_mode":           applied,
			})
		}
		fmt.Printf("Installed %s@%s\n", pv.Name, pv.Version)
		fmt.Printf("Policy written: %s\n", path)
		fmt.Printf("Compiled policy: %s\n", compiledPath)
		fmt.Printf("Applied mode: %s\n", applied)
		if applied == "shadow" {
			fmt.Printf("Next: when ready for enforcement, run: faramesh pack enforce %s@%s\n", pv.Name, pv.Version)
		}
		return nil
	},
}

var hubDisableCmd = &cobra.Command{
	Use:   "disable [pack-ref]",
	Short: "Disable an installed policy pack version",
	Long:  `Mark an installed pack version as disabled by writing disabled.json. Reference format requires a version: org/pack@1.2.3.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name, ver, err := parsePackRefWithRequiredVersion(args[0])
		if err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		reason := strings.TrimSpace(hubDisableReason)
		if reason == "" {
			reason = "manually disabled"
		}
		manifestPath, err := hub.DisableInstalledPack(root, name, ver, reason, nil)
		if err != nil {
			if errors.Is(err, hub.ErrPackNotInstalled) {
				return fmt.Errorf("pack is not installed: %s@%s", name, ver)
			}
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":            true,
				"name":          name,
				"version":       ver,
				"disabled":      true,
				"disabled_path": manifestPath,
			})
		}
		fmt.Printf("Disabled %s@%s\n", name, ver)
		fmt.Printf("Disabled manifest: %s\n", manifestPath)
		return nil
	},
}

var hubEnableCmd = &cobra.Command{
	Use:   "enable [pack-ref]",
	Short: "Enable a previously disabled policy pack version",
	Long:  `Enable an installed pack version by removing disabled.json. Reference format requires a version: org/pack@1.2.3.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name, ver, err := parsePackRefWithRequiredVersion(args[0])
		if err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		if err := hub.EnableInstalledPack(root, name, ver); err != nil {
			if errors.Is(err, hub.ErrPackNotInstalled) {
				return fmt.Errorf("pack is not installed: %s@%s", name, ver)
			}
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":       true,
				"name":     name,
				"version":  ver,
				"disabled": false,
			})
		}
		fmt.Printf("Enabled %s@%s\n", name, ver)
		return nil
	},
}

var hubStatusCmd = &cobra.Command{
	Use:   "status [pack-ref]",
	Short: "Show local lifecycle status for an installed policy pack version",
	Long: `Inspect whether an installed pack version is active or disabled.
Reference: org/pack@1.2.3, or org/pack to use the latest installed version for that name.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		name, ver, err := resolvePackRefForLocalInstall(root, args[0])
		if err != nil {
			return err
		}
		status, err := hub.PackStatus(root, name, ver)
		if err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(status)
		}
		emitInstalledPackLifecycleText(name, ver, status)
		return nil
	},
}

var hubVerifyCmd = &cobra.Command{
	Use:   "verify [pack-ref]",
	Short: "Verify pack integrity (SHA-256 and optional Ed25519 signature)",
	Long: `Verify a pack from the registry. Checks sha256_hex and, when present,
Ed25519 signature over raw policy YAML using public_key_pem from the response.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ref := args[0]
		name, ver, err := hub.ParsePackRef(ref)
		if err != nil {
			return err
		}
		if ver == "" {
			ver = "latest"
		}
		c, err := hubClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		pv, err := c.GetPackVersion(ctx, name, ver)
		if err != nil {
			return err
		}
		if err := hub.ValidatePackPayload(pv); err != nil {
			return err
		}
		if hubRequireSig && pv.Signature == nil {
			return fmt.Errorf("pack is unsigned (--require-signature)")
		}
		if hubRequireVerifiedPublisher {
			admission := hub.EvaluateInstallAdmissionWithOptions(pv, hub.InstallAdmissionOptions{
				RequireVerifiedPublisher: true,
			})
			if !admission.Allowed {
				return fmt.Errorf("publisher verification failed: %v", admission.Findings)
			}
		}
		out := map[string]any{
			"name":              pv.Name,
			"version":           pv.Version,
			"sha256_ok":         true,
			"signature_present": pv.Signature != nil,
			"signature_ok":      pv.Signature != nil,
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		fmt.Printf("OK: checksum verified for %s@%s\n", pv.Name, pv.Version)
		if pv.Signature != nil {
			fmt.Println("OK: Ed25519 signature verified")
		} else {
			color.Yellow("Pack is unsigned (no signature block in registry response).")
		}
		return nil
	},
}

var hubPublishCmd = &cobra.Command{
	Use:   "publish [path]",
	Short: "Publish a policy pack to a compatible registry",
	Long: `Upload policy YAML to POST /v1/packs. Requires --name, --version, and --hub-token
unless FARAMESH_HUB_TOKEN is set. Path may be a file or a directory containing policy.yaml.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		policy, err := loadPolicyYAML(args[0])
		if err != nil {
			return err
		}
		c, err := hubClient()
		if err != nil {
			return err
		}
		if c.AuthBearer == "" {
			return fmt.Errorf("publish requires --hub-token or FARAMESH_HUB_TOKEN")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := c.Publish(ctx, hub.PublishRequest{
			Name:       hubPublishName,
			Version:    hubPublishVersion,
			PolicyYAML: policy,
		}); err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "ok"})
		}
		fmt.Println("Publish accepted by registry.")
		return nil
	},
}

func loadPolicyYAML(p string) (string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		b, err := os.ReadFile(filepath.Join(p, "policy.yaml"))
		if err != nil {
			return "", fmt.Errorf("read %s/policy.yaml: %w", p, err)
		}
		return string(b), nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parsePackRefWithRequiredVersion(ref string) (string, string, error) {
	name, version, err := hub.ParsePackRef(ref)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(version) == "" {
		return "", "", fmt.Errorf("pack reference must include a version: org/pack@x.y.z")
	}
	return name, version, nil
}
