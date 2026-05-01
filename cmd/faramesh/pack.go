package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/hub"
	seedpacks "github.com/faramesh/faramesh-core/packs"
)

var packCmd = &cobra.Command{
	Use:   "pack",
	Short: "Manage policy packs",
	Long: `Search, inspect, install, diff, upgrade, and publish policy packs.
This is the product-facing command group over the Hub registry client.`,
}

func init() {
	packCmd.PersistentFlags().StringVar(&hubURL, "hub-url", "", "registry base URL (or FARAMESH_HUB_URL)")
	packCmd.PersistentFlags().StringVar(&hubToken, "hub-token", "", "Bearer token for publish (or FARAMESH_HUB_TOKEN)")
	packCmd.PersistentFlags().StringVar(&hubOrgID, "org-id", "", "org id for private catalog scope (or FARAMESH_HUB_ORG)")
	packCmd.PersistentFlags().BoolVar(&hubJSON, "json", false, "machine-readable JSON output")

	packInstallCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	packInstallCmd.Flags().StringVar(&packInstallMode, "mode", "enforce", "install mode: enforce|shadow")
	packInstallCmd.Flags().StringVar(&hubQuarantineRoot, "quarantine-root", "", "quarantine root for rejected packs (default: ~/.faramesh/hub/quarantine)")
	packInstallCmd.Flags().StringVar(&hubAdmissionMode, "admission-mode", "enforce", "install admission mode: off|warn|enforce")
	packInstallCmd.Flags().StringVar(&hubDisableReason, "disable-reason", "install admission failed", "reason recorded when a pack is disabled by admission")
	packInstallCmd.Flags().StringVar(&hubTrust, "trust", "verified", "trust tier acknowledgment: verified|community")
	packInstallCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned or signature invalid")
	packInstallCmd.Flags().BoolVar(&hubRequireVerifiedPublisher, "require-verified-publisher", false, "reject packs without a registry-verified publisher identity")

	packListCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	packInfoCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned or signature invalid")
	packPreviewCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned or signature invalid")
	packDiffCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	packStatusCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	packShadowCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	packEnforceCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")

	packPublishCmd.Flags().StringVar(&hubPublishName, "name", "", "pack name (e.g. org/pack)")
	packPublishCmd.Flags().StringVar(&hubPublishVersion, "version", "", "semver (e.g. 1.0.0)")
	_ = packPublishCmd.MarkFlagRequired("name")
	_ = packPublishCmd.MarkFlagRequired("version")

	packSearchCmd.Flags().StringVar(&hubSearchVisibility, "visibility", "", "catalog filter: public|org|all (registry-supported)")

	packCmd.AddCommand(packSearchCmd, packInstallCmd, packInfoCmd, packPreviewCmd, packDiffCmd, packUpgradeCmd, packStatusCmd, packShadowCmd, packEnforceCmd, packListCmd, packPublishCmd)
	rootCmd.AddCommand(packCmd)
}

var packSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search policy packs",
	Args:  hubSearchCmd.Args,
	RunE: func(_ *cobra.Command, args []string) error {
		query := ""
		if len(args) > 0 {
			query = args[0]
		}
		results, err := searchPackCatalog(query)
		if err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(hub.SearchResponse{APIVersion: hub.APIVersion, Packs: results})
		}
		if len(results) == 0 {
			fmt.Println("No packs matched.")
			return nil
		}
		fmt.Printf("%-40s %-12s %-12s %s\n", "PACK", "VERSION", "TRUST", "DESCRIPTION")
		for _, item := range results {
			fmt.Printf("%-40s %-12s %-12s %s\n", item.Name, item.LatestVersion, valueOrDefault(item.TrustTier, "unspecified"), item.Description)
		}
		return nil
	},
}

var packInstallCmd = &cobra.Command{
	Use:   "install [pack-ref]",
	Short: "Install a policy pack",
	Args:  hubInstallCmd.Args,
	RunE:  hubInstallCmd.RunE,
}

var packPublishCmd = &cobra.Command{
	Use:   "publish [path]",
	Short: "Publish a policy pack",
	Args:  hubPublishCmd.Args,
	RunE:  hubPublishCmd.RunE,
}

var packInfoCmd = &cobra.Command{
	Use:   "info [pack-ref]",
	Short: "Show pack metadata",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		pv, err := fetchPackVersion(args[0])
		if err != nil {
			return err
		}
		return emitPackMetadata(pv, false)
	},
}

var packPreviewCmd = &cobra.Command{
	Use:   "preview [pack-ref]",
	Short: "Preview pack summary and starter policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		pv, err := fetchPackVersion(args[0])
		if err != nil {
			return err
		}
		return emitPackMetadata(pv, true)
	},
}

var packUpgradeCmd = &cobra.Command{
	Use:   "upgrade [pack-name]",
	Short: "Install the latest version of an existing pack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return hubInstallCmd.RunE(cmd, []string{args[0]})
	},
}

var packStatusCmd = &cobra.Command{
	Use:   "status [pack-ref]",
	Short: "Show local install status, applied mode, and policy artifact paths",
	Long: `Inspect an installed pack: shadow vs enforce, trust tier, policy.yaml paths,
and optional policy.fpl / policy.compiled.yaml when present.
Reference: org/pack@1.2.3, or org/pack for the latest installed version.`,
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
		st, err := hub.PackStatus(root, name, ver)
		if err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(st)
		}
		emitInstalledPackLifecycleText(name, ver, st)
		return nil
	},
}

var packShadowCmd = &cobra.Command{
	Use:   "shadow [pack-ref]",
	Short: "Switch an installed pack to shadow (observe-first) mode",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name, ver, err := hub.ParsePackRef(args[0])
		if err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		if strings.TrimSpace(ver) == "" {
			ver, err = latestInstalledVersion(root, name)
			if err != nil {
				return err
			}
		}
		if err := hub.SetInstalledPackMode(root, name, ver, "shadow"); err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":           true,
				"name":         name,
				"version":      ver,
				"applied_mode": "shadow",
			})
		}
		fmt.Printf("Set %s@%s to shadow mode\n", name, ver)
		return nil
	},
}

var packEnforceCmd = &cobra.Command{
	Use:   "enforce [pack-ref]",
	Short: "Switch an installed pack to enforce mode",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name, ver, err := hub.ParsePackRef(args[0])
		if err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		if strings.TrimSpace(ver) == "" {
			ver, err = latestInstalledVersion(root, name)
			if err != nil {
				return err
			}
		}
		if err := hub.SetInstalledPackMode(root, name, ver, "enforce"); err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":           true,
				"name":         name,
				"version":      ver,
				"applied_mode": "enforce",
			})
		}
		fmt.Printf("Set %s@%s to enforce mode\n", name, ver)
		return nil
	},
}

var packListCmd = &cobra.Command{
	Use:   "list",
	Short: "List locally installed packs",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		items, err := listInstalledPacks(root)
		if err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(items)
		}
		if len(items) == 0 {
			fmt.Println("No packs installed.")
			return nil
		}
		fmt.Printf("%-36s %-12s %-10s %-8s %-4s %-4s %s\n", "PACK", "VERSION", "TRUST", "MODE", "FPL", "CMP", "DESCRIPTION")
		for _, item := range items {
			fpl := "-"
			if item.HasFPL {
				fpl = "yes"
			}
			cmp := "-"
			if item.HasCompiled {
				cmp = "yes"
			}
			fmt.Printf("%-36s %-12s %-10s %-8s %-4s %-4s %s\n", item.Name, item.Version, item.TrustTier, valueOrDefault(item.AppliedMode, "enforce"), fpl, cmp, item.Description)
		}
		return nil
	},
}

var packDiffCmd = &cobra.Command{
	Use:   "diff [pack-ref]",
	Short: "Compare a remote pack against the installed local copy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		pv, err := fetchPackVersion(args[0])
		if err != nil {
			return err
		}
		root, err := hubInstallRootPath()
		if err != nil {
			return err
		}
		localVersion := pv.Version
		if localVersion == "latest" || strings.TrimSpace(localVersion) == "" {
			localVersion, err = latestInstalledVersion(root, pv.Name)
			if err != nil {
				return err
			}
		}
		localPolicyPath := filepath.Join(hub.PackInstallDir(root, pv.Name, localVersion), "policy.yaml")
		localPolicy, err := os.ReadFile(localPolicyPath)
		if err != nil {
			return fmt.Errorf("read local installed policy %s: %w", localPolicyPath, err)
		}
		if string(localPolicy) == pv.PolicyYAML {
			if hubJSON {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"name":           pv.Name,
					"remote_version": pv.Version,
					"local_version":  localVersion,
					"changed":        false,
				})
			}
			fmt.Printf("No policy diff for %s (local %s matches remote %s)\n", pv.Name, localVersion, pv.Version)
			return nil
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"name":           pv.Name,
				"remote_version": pv.Version,
				"local_version":  localVersion,
				"changed":        true,
				"local_policy":   string(localPolicy),
				"remote_policy":  pv.PolicyYAML,
			})
		}
		fmt.Printf("Policy diff for %s\n", pv.Name)
		fmt.Printf("--- local %s\n", localVersion)
		fmt.Printf("+++ remote %s\n", pv.Version)
		fmt.Println(renderSimplePolicyDiff(string(localPolicy), pv.PolicyYAML))
		return nil
	},
}

func fetchPackVersion(ref string) (*hub.PackVersionResponse, error) {
	name, ver, err := hub.ParsePackRef(ref)
	if err != nil {
		return nil, err
	}
	pv, err := resolvePackVersion(name, ver)
	if err != nil {
		return nil, err
	}
	if hubRequireSig && pv.Signature == nil {
		return nil, fmt.Errorf("pack is unsigned (--require-signature)")
	}
	if err := hub.ValidatePackPayload(pv); err != nil {
		return nil, err
	}
	return pv, nil
}

func resolvePackVersion(name, ver string) (*hub.PackVersionResponse, error) {
	if strings.TrimSpace(ver) == "" {
		ver = "latest"
	}
	if strings.TrimSpace(hubURL) != "" {
		c, err := hubClient()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if pv, fetchErr := c.GetPackVersion(ctx, name, ver); fetchErr == nil {
				return pv, nil
			}
		}
	}
	return seedpacks.Lookup(name, ver)
}

func searchPackCatalog(query string) ([]hub.PackSummary, error) {
	if strings.TrimSpace(hubURL) != "" {
		c, err := hubClient()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var opts *hub.SearchOptions
			if v := strings.TrimSpace(hubSearchVisibility); v != "" {
				opts = &hub.SearchOptions{Visibility: v}
			}
			if sr, searchErr := c.Search(ctx, query, opts); searchErr == nil {
				return sr.Packs, nil
			}
		}
	}
	return seedpacks.Search(query), nil
}

func emitPackMetadata(pv *hub.PackVersionResponse, preview bool) error {
	if hubJSON {
		return json.NewEncoder(os.Stdout).Encode(pv)
	}
	fmt.Printf("%s@%s\n", pv.Name, pv.Version)
	if pv.Description != "" {
		fmt.Printf("%s\n", pv.Description)
	}
	fmt.Printf("Trust tier: %s\n", valueOrDefault(pv.TrustTier, "unspecified"))
	if pv.Publisher != nil {
		fmt.Printf("Publisher: %s", valueOrDefault(pv.Publisher.DisplayName, pv.Publisher.ID))
		if pv.Publisher.Verified {
			fmt.Printf(" (verified)")
		}
		fmt.Println()
	}
	if pv.RiskModel != nil {
		fmt.Printf("Risk: severity=%s blast_radius=%s categories=%s\n",
			valueOrDefault(pv.RiskModel.Severity, "unspecified"),
			valueOrDefault(pv.RiskModel.BlastRadius, "unspecified"),
			strings.Join(pv.RiskModel.Categories, ", "))
	}
	if len(pv.SupportedFrameworks) > 0 {
		fmt.Printf("Frameworks: %s\n", strings.Join(pv.SupportedFrameworks, ", "))
	}
	if len(pv.ActionSurfaces) > 0 {
		fmt.Printf("Action surfaces: %s\n", strings.Join(pv.ActionSurfaces, ", "))
	}
	if len(pv.Assumptions) > 0 {
		fmt.Println("Assumptions:")
		for _, item := range pv.Assumptions {
			fmt.Printf("- %s\n", item)
		}
	}
	if pv.RulesSummary != nil {
		fmt.Println("Starter rules:")
		printSummaryList("permit", pv.RulesSummary.Permit)
		printSummaryList("defer", pv.RulesSummary.Defer)
		printSummaryList("deny", pv.RulesSummary.Deny)
	}
	if pv.ObserveEnforce != nil {
		fmt.Printf("Observe period: %s\n", valueOrDefault(pv.ObserveEnforce.ObservePeriod, "not specified"))
		for _, stage := range pv.ObserveEnforce.EnforcementStages {
			fmt.Printf("- stage=%s duration=%s %s\n", stage.Stage, valueOrDefault(stage.Duration, "n/a"), stage.Description)
		}
	}
	if strings.TrimSpace(pv.PolicyFPL) != "" {
		n := len(strings.TrimSpace(pv.PolicyFPL))
		fmt.Printf("Pack includes authored FPL sidecar (%d bytes non-whitespace)\n", n)
	}
	if preview {
		fmt.Println()
		fmt.Println("Policy preview:")
		lines := strings.Split(pv.PolicyYAML, "\n")
		limit := len(lines)
		if limit > 20 {
			limit = 20
		}
		for _, line := range lines[:limit] {
			fmt.Println(line)
		}
		if len(lines) > limit {
			fmt.Println("...")
		}
		if strings.TrimSpace(pv.PolicyFPL) != "" {
			fmt.Println()
			fmt.Println("FPL preview (first lines):")
			fl := strings.Split(pv.PolicyFPL, "\n")
			flimit := len(fl)
			if flimit > 12 {
				flimit = 12
			}
			for _, line := range fl[:flimit] {
				fmt.Println(line)
			}
			if len(fl) > flimit {
				fmt.Println("...")
			}
		}
	}
	return nil
}

type installedPackRow struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	TrustTier   string `json:"trust_tier,omitempty"`
	Description string `json:"description,omitempty"`
	AppliedMode string `json:"applied_mode,omitempty"`
	Disabled    bool   `json:"disabled"`
	HasFPL      bool   `json:"has_policy_fpl,omitempty"`
	HasCompiled bool   `json:"has_policy_compiled,omitempty"`
}

func listInstalledPacks(root string) ([]installedPackRow, error) {
	var rows []installedPackRow
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "manifest.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var man hub.ManifestSidecar
		if err := json.Unmarshal(data, &man); err != nil {
			return err
		}
		dir := filepath.Dir(path)
		disabledPath := filepath.Join(dir, "disabled.json")
		_, disabledErr := os.Stat(disabledPath)
		_, hasFPL := os.Stat(filepath.Join(dir, "policy.fpl"))
		_, hasCompiled := os.Stat(filepath.Join(dir, "policy.compiled.yaml"))
		rows = append(rows, installedPackRow{
			Name:        man.Name,
			Version:     man.Version,
			TrustTier:   man.TrustTier,
			Description: man.Description,
			AppliedMode: man.AppliedMode,
			Disabled:    disabledErr == nil,
			HasFPL:      hasFPL == nil,
			HasCompiled: hasCompiled == nil,
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name == rows[j].Name {
			return rows[i].Version < rows[j].Version
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, nil
}

func latestInstalledVersion(root, name string) (string, error) {
	dir := filepath.Join(root, strings.ReplaceAll(name, "/", string(filepath.Separator)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("pack %s is not installed locally", name)
	}
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("pack %s is not installed locally", name)
	}
	sort.Strings(versions)
	return versions[len(versions)-1], nil
}

func renderSimplePolicyDiff(localPolicy, remotePolicy string) string {
	localLines := strings.Split(localPolicy, "\n")
	remoteLines := strings.Split(remotePolicy, "\n")
	max := len(localLines)
	if len(remoteLines) > max {
		max = len(remoteLines)
	}
	var out []string
	for i := 0; i < max; i++ {
		var local, remote string
		if i < len(localLines) {
			local = localLines[i]
		}
		if i < len(remoteLines) {
			remote = remoteLines[i]
		}
		if local == remote {
			continue
		}
		if local != "" {
			out = append(out, "- "+local)
		}
		if remote != "" {
			out = append(out, "+ "+remote)
		}
	}
	return strings.Join(out, "\n")
}

func printSummaryList(label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("- %s:\n", label)
	for _, item := range items {
		fmt.Printf("  - %s\n", item)
	}
}

func valueOrDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func normalizePackInstallMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shadow":
		return "shadow"
	default:
		return "enforce"
	}
}
