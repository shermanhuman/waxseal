package cli

import (
	"fmt"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
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
	addMetadataCheck(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")

	// Load all metadata
	secrets, err := files.LoadAllMetadata(repoPath)
	if err != nil {
		if core.IsNotFound(err) {
			fmt.Println("No secrets registered. Run 'waxseal discover' first.")
			return nil
		}
		return err
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
			truncateStr(s.ShortName, 25),
			status,
			len(s.Keys),
			truncateStr(strings.Join(modeList, ", "), 30),
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
