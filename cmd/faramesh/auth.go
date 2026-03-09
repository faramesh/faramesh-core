package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/cloud"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Faramesh Horizon cloud",
	Long: `Manage authentication with Faramesh Horizon.

  faramesh auth login        Authenticate with Horizon
  faramesh auth logout       Remove stored credentials
  faramesh auth status       Show current authentication status`,
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Faramesh Horizon",
	Long: `Authenticate with Faramesh Horizon to enable fleet management,
compliance exports, and DPR sync.

You can authenticate with:
  1. A Horizon API token (from https://app.faramesh.io/settings/tokens)
  2. Interactive browser-based device flow

  faramesh auth login
  faramesh auth login --token <your-token>
  faramesh auth login --horizon-url https://self-hosted.company.com`,
	RunE: runAuthLogin,
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored Horizon credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cloud.DeleteToken(); err != nil {
			return fmt.Errorf("logout: %w", err)
		}
		color.Green("✓ Logged out of Faramesh Horizon")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current Horizon authentication status",
	Aliases: []string{"whoami"},
	RunE: runAuthStatus,
}

var (
	loginToken      string
	loginHorizonURL string
)

func init() {
	authLoginCmd.Flags().StringVar(&loginToken, "token", "", "API token (from https://app.faramesh.io/settings/tokens)")
	authLoginCmd.Flags().StringVar(&loginHorizonURL, "horizon-url", cloud.HorizonBaseURL, "Horizon API URL (for self-hosted)")
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	horizonURL := loginHorizonURL
	if horizonURL == "" {
		horizonURL = cloud.HorizonBaseURL
	}

	token := loginToken
	if token == "" {
		// Prompt for token interactively.
		fmt.Println()
		bold.Println("Faramesh Horizon Login")
		fmt.Println()
		fmt.Println("Get your API token from:")
		color.Cyan("  https://app.faramesh.io/settings/tokens")
		fmt.Println()
		fmt.Print("Enter your API token: ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		token = strings.TrimSpace(line)
		if token == "" {
			return fmt.Errorf("token cannot be empty")
		}
	}

	// Validate the token against the Horizon API.
	fmt.Print("Authenticating with Horizon... ")
	info, err := validateToken(horizonURL, token)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Save the token.
	if err := cloud.SaveToken(info); err != nil {
		return fmt.Errorf("save token: %w", err)
	}

	fmt.Println()
	green.Println("✓ Authenticated with Faramesh Horizon")
	fmt.Println()
	fmt.Printf("  User:    %s\n", info.UserEmail)
	fmt.Printf("  Org:     %s (%s)\n", info.OrgName, info.OrgID)
	fmt.Printf("  Horizon: %s\n", info.HorizonURL)
	fmt.Println()
	fmt.Println("To sync DPR records to Horizon, run:")
	color.Cyan("  faramesh serve --policy policy.yaml --sync-horizon")
	fmt.Println()
	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	info, err := cloud.LoadToken()
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}

	fmt.Println()
	if info == nil {
		color.Yellow("Not authenticated with Faramesh Horizon")
		fmt.Println()
		fmt.Println("Run: faramesh auth login")
		fmt.Println()
		return nil
	}

	if info.IsExpired() {
		color.Red("Token expired — please re-authenticate")
		fmt.Println()
		fmt.Println("Run: faramesh auth login")
		fmt.Println()
		return nil
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Println("✓ Authenticated with Faramesh Horizon")
	fmt.Println()
	fmt.Printf("  User:       %s\n", info.UserEmail)
	fmt.Printf("  Org:        %s (%s)\n", info.OrgName, info.OrgID)
	fmt.Printf("  Horizon:    %s\n", info.HorizonURL)
	fmt.Printf("  Token:      %s...\n", maskToken(info.Token))
	fmt.Printf("  Saved at:   %s\n", info.CreatedAt.Format(time.RFC822))
	if !info.ExpiresAt.IsZero() {
		fmt.Printf("  Expires:    %s\n", info.ExpiresAt.Format(time.RFC822))
	} else {
		fmt.Printf("  Expires:    never\n")
	}
	fmt.Println()
	return nil
}

// validateToken calls the Horizon /v1/auth/me endpoint to verify the token.
// Returns the token info on success.
func validateToken(horizonURL, token string) (*cloud.TokenInfo, error) {
	url := horizonURL + "/v1/auth/me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "faramesh-cli/"+version)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Horizon might not be reachable — allow offline token storage with a warning.
		if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "connection refused") {
			color.Yellow("⚠ Could not reach Horizon API — storing token for when connectivity is available")
			return &cloud.TokenInfo{
				Token:      token,
				HorizonURL: horizonURL,
				CreatedAt:  time.Now(),
			}, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from Horizon API", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var me struct {
		Email   string `json:"email"`
		OrgID   string `json:"org_id"`
		OrgName string `json:"org_name"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, fmt.Errorf("parse Horizon response: %w", err)
	}

	return &cloud.TokenInfo{
		Token:      token,
		OrgID:      me.OrgID,
		OrgName:    me.OrgName,
		UserEmail:  me.Email,
		HorizonURL: horizonURL,
		CreatedAt:  time.Now(),
	}, nil
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:8] + strings.Repeat("*", min(len(token)-8, 20))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
