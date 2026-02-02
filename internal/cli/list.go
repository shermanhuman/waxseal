package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered secrets and their rotation modes",
	Long: `List all secrets registered in .waxseal/metadata/.

Shows shortName, status, key count, rotation modes, and expiration status.`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().StringP("output", "o", "table", "Output format: table, json")
}

func runList(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")

	// Load all metadata
	metadataDir := filepath.Join(repoPath, ".waxseal", "metadata")
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No secrets registered. Run 'waxseal discover' first.")
			return nil
		}
		return fmt.Errorf("read metadata directory: %w", err)
	}

	var secrets []*core.SecretMetadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(metadataDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		m, err := core.ParseMetadata(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		secrets = append(secrets, m)
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets registered. Run 'waxseal discover' first.")
		return nil
	}

	if output == "json" {
		return printListJSON(secrets)
	}

	return printListTable(secrets)
}

func printListTable(secrets []*core.SecretMetadata) error {
	// Header
	fmt.Printf("%-25s %-10s %-6s %-30s %-20s\n", "SHORT NAME", "STATUS", "KEYS", "ROTATION MODES", "EXPIRY")
	fmt.Println(strings.Repeat("-", 95))

	for _, s := range secrets {
		status := s.Status
		if status == "" {
			status = "active"
		}

		// Collect rotation modes
		modes := make(map[string]bool)
		for _, k := range s.Keys {
			if k.Rotation != nil {
				modes[k.Rotation.Mode] = true
			} else if k.Source.Kind == "computed" {
				modes["computed"] = true
			}
		}
		modeList := make([]string, 0, len(modes))
		for m := range modes {
			modeList = append(modeList, m)
		}

		// Check expiry
		expiry := ""
		if s.IsExpired() {
			expiry = "EXPIRED"
		} else if s.ExpiresWithinDays(30) {
			expiry = "expiring soon"
		}

		fmt.Printf("%-25s %-10s %-6d %-30s %-20s\n",
			truncate(s.ShortName, 25),
			status,
			len(s.Keys),
			truncate(strings.Join(modeList, ", "), 30),
			expiry,
		)
	}

	return nil
}

func printListJSON(secrets []*core.SecretMetadata) error {
	fmt.Println("[")
	for i, s := range secrets {
		status := s.Status
		if status == "" {
			status = "active"
		}

		expired := s.IsExpired()
		expiringSoon := s.ExpiresWithinDays(30)

		comma := ","
		if i == len(secrets)-1 {
			comma = ""
		}

		fmt.Printf(`  {"shortName": %q, "status": %q, "keyCount": %d, "expired": %v, "expiringSoon": %v}%s
`,
			s.ShortName, status, len(s.Keys), expired, expiringSoon, comma)
	}
	fmt.Println("]")
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
