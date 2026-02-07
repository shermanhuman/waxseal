// Package cli provides the Cobra command structure for waxseal.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	repoPath   string
	configPath string
	dryRun     bool
	yes        bool
)

// Version information (can be overridden at build time via ldflags)
var (
	Version   = "0.4.0"
	Commit    = "dev"
	BuildDate = "unknown"
)

// rootCmd is the base command for waxseal.
var rootCmd = &cobra.Command{
	Use:   "waxseal",
	Short: "GitOps-friendly SealedSecrets management with GSM as source of truth",
	Long: `waxseal makes SealedSecrets GitOps-friendly by keeping plaintext out of Git.

Source of truth:
  - All plaintext secret values live in Google Secret Manager (GSM)
  - Git stores SealedSecret manifests (ciphertext) and metadata

Run 'waxseal help advanced' for non-interactive / scripting commands.`,
	Version: Version,
}

// Command group IDs
const (
	groupKeyMgmt      = "key-management"
	groupOps          = "operations"
	groupMeta         = "metadata"
	groupInstallation = "installation"
)

// advancedCmd shows the advanced help output.
var advancedCmd = &cobra.Command{
	Use:   "advanced",
	Short: "Show advanced commands",
	Long: `Show advanced commands for scripting, CI, and power-user workflows.

These commands are fully functional but hidden from the primary help
to keep the default output focused on daily operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Advanced Commands:")
		fmt.Println()
		fmt.Println("Key Management (non-interactive):")
		fmt.Printf("  %-20s %s\n", "addkey", "Add a key to a secret (or create a new secret)")
		fmt.Printf("  %-20s %s\n", "updatekey", "Update an existing key's value")
		fmt.Printf("  %-20s %s\n", "retirekey", "Mark a key as retired")
		fmt.Println()
		fmt.Println("Validation (individual checks):")
		fmt.Printf("  %-20s %s\n", "check cert", "Certificate health only")
		fmt.Printf("  %-20s %s\n", "check expiry", "Secret expiration only")
		fmt.Printf("  %-20s %s\n", "check metadata", "Config/schema/hygiene validation")
		fmt.Printf("  %-20s %s\n", "check gsm", "Verify GSM secret versions exist")
		fmt.Printf("  %-20s %s\n", "check cluster", "Compare metadata vs live cluster keys")
		fmt.Println()
		fmt.Println("Discovery & Bootstrap:")
		fmt.Printf("  %-20s %s\n", "discover", "Scan repo for SealedSecret manifests")
		fmt.Printf("  %-20s %s\n", "gsm bootstrap", "Push secrets from cluster to GSM")
		fmt.Printf("  %-20s %s\n", "gsm gcp-bootstrap", "Initialize GCP infrastructure")
		fmt.Println()
		fmt.Println("Reminders:")
		fmt.Printf("  %-20s %s\n", "reminders sync", "Sync calendar/task reminders")
		fmt.Printf("  %-20s %s\n", "reminders list", "List upcoming expirations")
		fmt.Printf("  %-20s %s\n", "reminders clear", "Clear reminders for retired secrets")
		fmt.Printf("  %-20s %s\n", "reminders setup", "Configure reminder providers")
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&repoPath, "repo", ".", "Path to the GitOps repository")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", ".waxseal/config.yaml", "Path to waxseal config file")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	rootCmd.PersistentFlags().BoolVar(&yes, "yes", false, "Skip confirmation prompts (where applicable)")

	// Custom version template to show commit and build date
	rootCmd.SetVersionTemplate(`waxseal {{.Version}}
Commit: ` + Commit + `
Built:  ` + BuildDate + `
`)

	// Command groups for organized help output
	rootCmd.AddGroup(
		&cobra.Group{ID: groupKeyMgmt, Title: "Key Management:"},
		&cobra.Group{ID: groupOps, Title: "Operations:"},
		&cobra.Group{ID: groupMeta, Title: "Metadata:"},
		&cobra.Group{ID: groupInstallation, Title: "Installation:"},
	)

	// Add "help advanced" command
	rootCmd.AddCommand(advancedCmd)
}

// Execute runs the root command.
func Execute() error {
	// Disable Cobra's default error printing
	rootCmd.SilenceErrors = true

	err := rootCmd.Execute()
	if err != nil {
		// Print error with red color and proper spacing
		fmt.Fprintf(os.Stderr, "\n%sError: %s%s\n\n", styleRed, err.Error(), styleReset)
	}
	return err
}

// requiresMetadata returns true if the command needs .waxseal/metadata to exist.
func requiresMetadata(cmdName string) bool {
	commands := map[string]bool{
		"list":      true,
		"secrets":   true,
		"keys":      true,
		"showkey":   true,
		"check":     true,
		"reseal":    true,
		"rotate":    true,
		"retirekey": true,
	}
	return commands[cmdName]
}

// checkMetadataExists checks if .waxseal/ exists and offers to run discover if not.
// Returns true if metadata exists or was created, false if we should abort.
func checkMetadataExists(cmd *cobra.Command) (bool, error) {
	// Skip check for commands that don't need metadata
	if !requiresMetadata(cmd.Name()) {
		return true, nil
	}

	metadataDir := filepath.Join(repoPath, ".waxseal", "metadata")
	configFile := filepath.Join(repoPath, ".waxseal", "config.yaml")

	// Check if config exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No waxseal configuration found at %s\n", configFile)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run 'waxseal setup' to set up waxseal in this repository.")
		return false, nil
	}

	// Check if metadata directory exists
	if _, err := os.Stat(metadataDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No secret metadata found at %s\n", metadataDir)
		fmt.Fprintln(os.Stderr, "")

		if yes {
			// Auto-run discover with --yes flag
			fmt.Fprintln(os.Stderr, "Running 'waxseal discover --non-interactive'...")
			return runDiscoverNonInteractive()
		}

		// Prompt user
		ok, err := confirm("Run 'waxseal discover' to find existing SealedSecrets?")
		if err != nil {
			return false, err
		}
		if ok {
			return runDiscoverNonInteractive()
		}

		fmt.Fprintln(os.Stderr, "\nNo metadata found. Run 'waxseal discover' to create metadata stubs.")
		return false, nil
	}

	// Check if metadata directory is empty
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		return false, fmt.Errorf("read metadata directory: %w", err)
	}

	hasYAML := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			hasYAML = true
			break
		}
	}

	if !hasYAML {
		fmt.Fprintf(os.Stderr, "Metadata directory is empty: %s\n", metadataDir)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run 'waxseal discover' to find and register SealedSecrets.")
		return false, nil
	}

	return true, nil
}

// runDiscoverNonInteractive runs the discover command in non-interactive mode.
func runDiscoverNonInteractive() (bool, error) {
	// Create metadata directory
	metadataDir := filepath.Join(repoPath, ".waxseal", "metadata")
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		return false, fmt.Errorf("create metadata directory: %w", err)
	}

	// Run discover logic
	// For now, just create the directory and return success
	// The discover command will populate it
	fmt.Fprintln(os.Stderr, "Created metadata directory. Run 'waxseal discover' to populate.")
	return false, nil
}

// addMetadataCheck adds the auto-bootstrap check to a command.
func addMetadataCheck(cmd *cobra.Command) {
	originalPreRunE := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		ok, err := checkMetadataExists(c)
		if err != nil {
			return err
		}
		if !ok {
			// Exit without error - user declined or needs to run init/discover
			os.Exit(0)
		}
		if originalPreRunE != nil {
			return originalPreRunE(c, args)
		}
		return nil
	}
}
