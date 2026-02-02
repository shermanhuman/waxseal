// Package cli provides the Cobra command structure for waxseal.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	// Global flags
	repoPath   string
	configPath string
	dryRun     bool
	yes        bool
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
}

func init() {
	rootCmd.PersistentFlags().StringVar(&repoPath, "repo", ".", "Path to the GitOps repository")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", ".waxseal/config.yaml", "Path to waxseal config file")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	rootCmd.PersistentFlags().BoolVar(&yes, "yes", false, "Skip confirmation prompts (where applicable)")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
