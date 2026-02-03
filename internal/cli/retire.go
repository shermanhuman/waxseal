package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/spf13/cobra"
)

var retireCmd = &cobra.Command{
	Use:   "retire <shortName>",
	Short: "Mark a secret as retired",
	Long: `Mark a secret as retired and optionally remove its manifest.

Retirement is a two-phase process:
  1. Mark the secret as retired (status: retired)
  2. After consumers are removed, delete the manifest

Examples:
  # Mark a secret as retired with a reason
  waxseal retire my-old-secret --reason "Replaced by new-secret"

  # Mark as retired and point to replacement
  waxseal retire my-old-secret --replaced-by new-secret

  # Also delete the manifest file
  waxseal retire my-old-secret --delete-manifest

  # Also clear calendar reminders
  waxseal retire my-old-secret --clear-reminders`,
	Args: cobra.ExactArgs(1),
	RunE: runRetire,
}

var (
	retireReason         string
	retireReplacedBy     string
	retireDeleteManifest bool
	retireClearReminders bool
)

func init() {
	rootCmd.AddCommand(retireCmd)
	retireCmd.Flags().StringVar(&retireReason, "reason", "", "Reason for retirement")
	retireCmd.Flags().StringVar(&retireReplacedBy, "replaced-by", "", "Short name of replacement secret")
	retireCmd.Flags().BoolVar(&retireDeleteManifest, "delete-manifest", false, "Also delete the SealedSecret manifest file")
	retireCmd.Flags().BoolVar(&retireClearReminders, "clear-reminders", false, "Also clear calendar reminders for this secret")
	addMetadataCheck(retireCmd)
}

func runRetire(cmd *cobra.Command, args []string) error {
	shortName := args[0]

	// Load metadata
	metadataPath := filepath.Join(repoPath, ".waxseal", "metadata", shortName+".yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("secret %q not found", shortName)
		}
		return fmt.Errorf("read metadata: %w", err)
	}

	metadata, err := core.ParseMetadata(data)
	if err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	// Check if already retired
	if metadata.IsRetired() {
		fmt.Printf("Secret %q is already retired (at %s)\n", shortName, metadata.RetiredAt)
		return nil
	}

	// Update metadata
	metadata.Status = "retired"
	metadata.RetiredAt = time.Now().UTC().Format(time.RFC3339)
	if retireReason != "" {
		metadata.RetireReason = retireReason
	}
	if retireReplacedBy != "" {
		metadata.ReplacedBy = retireReplacedBy
	}

	if dryRun {
		fmt.Printf("[DRY RUN] Would retire secret %q\n", shortName)
		fmt.Printf("  Status: retired\n")
		fmt.Printf("  RetiredAt: %s\n", metadata.RetiredAt)
		if retireReason != "" {
			fmt.Printf("  Reason: %s\n", retireReason)
		}
		if retireReplacedBy != "" {
			fmt.Printf("  ReplacedBy: %s\n", retireReplacedBy)
		}
		if retireDeleteManifest {
			fmt.Printf("  Would delete manifest: %s\n", metadata.ManifestPath)
		}
		if retireClearReminders {
			fmt.Printf("  Would clear reminders\n")
		}
		return nil
	}

	// Write updated metadata
	updatedYAML := serializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(updatedYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	fmt.Printf("✓ Marked %q as retired\n", shortName)

	// Delete manifest if requested
	if retireDeleteManifest {
		manifestPath := metadata.ManifestPath
		if !filepath.IsAbs(manifestPath) {
			manifestPath = filepath.Join(repoPath, manifestPath)
		}

		if _, err := os.Stat(manifestPath); err == nil {
			if err := os.Remove(manifestPath); err != nil {
				return fmt.Errorf("delete manifest: %w", err)
			}
			fmt.Printf("✓ Deleted manifest: %s\n", metadata.ManifestPath)
		} else if os.IsNotExist(err) {
			fmt.Printf("  Manifest already deleted: %s\n", metadata.ManifestPath)
		}
	}

	// Clear reminders if requested
	if retireClearReminders {
		// Load config to check if reminders are enabled
		configFile := configPath
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(repoPath, configFile)
		}

		fmt.Printf("  Note: Use 'waxseal reminders clear %s' to remove calendar events\n", shortName)
	}

	// Print next steps
	if !retireDeleteManifest {
		fmt.Println("\nNext steps:")
		fmt.Printf("  1. Remove consumers of this secret\n")
		fmt.Printf("  2. Run: waxseal retire %s --delete-manifest\n", shortName)
	}

	return nil
}
