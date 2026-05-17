package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/registry"
	"github.com/spf13/cobra"
)

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Browse and inspect the Faramesh artifact catalog",
	Long: `Search providers, policy packs, and framework profiles.

Uses the public GitHub catalog by default, or FARAMESH_REGISTRY_ROOT / FARAMESH_REGISTRY_URL overrides.

  faramesh registry list
  faramesh registry search vault
  faramesh registry info frameworks/langgraph@1.0.0`,
}

var (
	registryListKind string
	registryListTier string
)

var registryListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List catalog artifacts",
	RunE:    runRegistryList,
}

var registrySearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search the catalog",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRegistrySearch,
}

var registryInfoCmd = &cobra.Command{
	Use:   "info <import-ref>",
	Short: "Show one artifact (e.g. frameworks/langgraph@1.0.0)",
	Args:  cobra.ExactArgs(1),
	RunE:  runRegistryInfo,
}

var registryURLCmd = &cobra.Command{
	Use:   "url",
	Short: "Print the configured registry base URL or local root",
	RunE:  runRegistryURL,
}

func init() {
	registryListCmd.Flags().StringVar(&registryListKind, "kind", "", "filter: provider, policy, framework")
	registryListCmd.Flags().StringVar(&registryListTier, "tier", "", "filter trust tier: official, community")
	registryCmd.AddCommand(registryListCmd, registrySearchCmd, registryInfoCmd, registryURLCmd)
}

func runRegistryList(_ *cobra.Command, _ []string) error {
	return printRegistryRows("", registryListKind, registryListTier)
}

func runRegistrySearch(_ *cobra.Command, args []string) error {
	q := ""
	if len(args) > 0 {
		q = args[0]
	}
	return printRegistryRows(q, registryListKind, registryListTier)
}

func printRegistryRows(q, kind, tier string) error {
	res, err := registry.NewResolver()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := res.Search(ctx, q, kind, tier)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no artifacts matched")
		return nil
	}
	for _, r := range rows {
		line := fmt.Sprintf("%-10s %-28s %-8s %s", r.Kind, r.Name, r.LatestVersion, r.Description)
		if r.TrustTier != "" {
			line += " [" + r.TrustTier + "]"
		}
		fmt.Println(line)
	}
	return nil
}

func runRegistryInfo(_ *cobra.Command, args []string) error {
	raw := strings.TrimSpace(args[0])
	if !strings.Contains(raw, "@") {
		raw = registry.DefaultHost + "/" + strings.TrimPrefix(raw, "/")
	}
	if !strings.Contains(raw, "registry.") && !strings.Contains(raw, "://") {
		// allow frameworks/langgraph@1.0.0
		parts := strings.SplitN(raw, "@", 2)
		if len(parts) == 2 {
			kind := "frameworks"
			if strings.HasPrefix(parts[0], "providers/") || strings.HasPrefix(parts[0], "faramesh/") {
				kind = "providers"
			} else if strings.HasPrefix(parts[0], "policies/") {
				kind = "policies"
			}
			raw = fmt.Sprintf("%s/%s/%s@%s", registry.DefaultHost, kind, strings.TrimPrefix(parts[0], "providers/"), parts[1])
		}
	}
	ref, err := registry.ParseImport(raw)
	if err != nil {
		return err
	}
	res, err := registry.NewResolver()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fmt.Println(ref.ImportLine())
	switch ref.Kind {
	case registry.KindProvider:
		pv, err := res.FetchProviderVersion(ctx, ref)
		if err != nil {
			return err
		}
		fmt.Printf("capabilities: %s\n", strings.Join(pv.Capabilities, ", "))
		for plat, dl := range pv.Downloads {
			fmt.Printf("  %s  sha256=%s  url=%s\n", plat, dl.SHA256Hex, dl.URL)
		}
		return nil
	case registry.KindPolicy, registry.KindFramework:
		pv, err := res.FetchFPLPack(ctx, ref)
		if err != nil {
			return err
		}
		body := pv.PolicyFPL
		if len(body) > 1200 {
			body = body[:1200] + "\n... (truncated)"
		}
		fmt.Println(body)
	default:
		return fmt.Errorf("unsupported kind %q", ref.Kind)
	}
	return nil
}

func runRegistryURL(_ *cobra.Command, _ []string) error {
	if root := registry.LocalCatalogRootFromEnv(); root != "" {
		fmt.Println(root)
		return nil
	}
	if v := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")); v != "" {
		fmt.Println(v)
		return nil
	}
	fmt.Println(registry.RegistryURLDescription())
	return nil
}
