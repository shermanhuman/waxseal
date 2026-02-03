// Package cli provides the Cobra command structure for waxseal.
package cli

import (
	"bufio"
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
	Version   = "0.1.4"
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

Primary commands:
  - waxseal reseal --all    Non-interactive ciphertext refresh
  - waxseal rotate          Value rotation with operator guidance
  - waxseal init            Happy-path onboarding`,
	Version: Version,
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
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// requiresMetadata returns true if the command needs .waxseal/metadata to exist.
func requiresMetadata(cmdName string) bool {
	commands := map[string]bool{
		"list":     true,
		"validate": true,
		"reseal":   true,
		"rotate":   true,
		"retire":   true,
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
		fmt.Fprintln(os.Stderr, "Run 'waxseal init' to set up waxseal in this repository.")
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
		fmt.Fprintln(os.Stderr, "Would you like to discover existing SealedSecrets?")
		fmt.Fprint(os.Stderr, "Run 'waxseal discover'? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "y" || input == "yes" {
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
