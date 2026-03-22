package main

import (
	"context"
	"encoding/json"
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
	hubURL            string
	hubToken          string
	hubJSON           bool
	hubInstallRoot    string
	hubRequireSig     bool
	hubPublishName    string
	hubPublishVersion string
	hubTrust          string
)

func init() {
	hubCmd.PersistentFlags().StringVar(&hubURL, "hub-url", "", "registry base URL (or FARAMESH_HUB_URL)")
	hubCmd.PersistentFlags().StringVar(&hubToken, "hub-token", "", "Bearer token for publish (or FARAMESH_HUB_TOKEN)")
	hubCmd.PersistentFlags().BoolVar(&hubJSON, "json", false, "machine-readable JSON output")

	hubInstallCmd.Flags().StringVar(&hubInstallRoot, "install-root", "", "pack install root (default: ~/.faramesh/hub/packs)")
	hubInstallCmd.Flags().StringVar(&hubTrust, "trust", "verified", "trust tier acknowledgment: verified|community (community packs require explicit opt-in)")
	hubInstallCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned or signature invalid")

	hubVerifyCmd.Flags().BoolVar(&hubRequireSig, "require-signature", false, "fail if pack is unsigned")

	hubPublishCmd.Flags().StringVar(&hubPublishName, "name", "", "pack name (e.g. org/pack)")
	hubPublishCmd.Flags().StringVar(&hubPublishVersion, "version", "", "semver (e.g. 1.0.0)")
	_ = hubPublishCmd.MarkFlagRequired("name")
	_ = hubPublishCmd.MarkFlagRequired("version")

	hubCmd.AddCommand(hubSearchCmd)
	hubCmd.AddCommand(hubInstallCmd)
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
		sr, err := c.Search(ctx, query)
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
		path, err := hub.WritePackToDisk(root, pv)
		if err != nil {
			return err
		}
		if hubJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{
				"policy_path": path,
				"name":        pv.Name,
				"version":     pv.Version,
				"sha256_hex":  hub.Sum256Hex([]byte(pv.PolicyYAML)),
			})
		}
		fmt.Printf("Installed %s@%s\n", pv.Name, pv.Version)
		fmt.Printf("Policy written: %s\n", path)
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
