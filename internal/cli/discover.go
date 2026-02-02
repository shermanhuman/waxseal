package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover SealedSecret manifests and create metadata stubs",
	Long: `Discover existing SealedSecret manifests in the repo and register them.

Creates .waxseal/metadata/<shortName>.yaml for each discovered SealedSecret.
Interactive mode prompts for GSM linkage and rotation intent.
Use --non-interactive for CI/automation to create stubs with unknown rotation.`,
	RunE: runDiscover,
}

var (
	discoverNonInteractive bool
)

func init() {
	rootCmd.AddCommand(discoverCmd)
	discoverCmd.Flags().BoolVar(&discoverNonInteractive, "non-interactive", false, "Create stubs without prompts (for CI)")
}

func runDiscover(cmd *cobra.Command, args []string) error {
	// Ensure .waxseal directory exists
	waxsealDir := filepath.Join(repoPath, ".waxseal")
	metadataDir := filepath.Join(waxsealDir, "metadata")

	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		return fmt.Errorf("create metadata directory: %w", err)
	}

	// Walk repo and find SealedSecrets
	var found []discoveredSecret
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip .waxseal, .git, etc.
		if info.IsDir() {
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Only look at YAML files
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		// Try to parse as SealedSecret
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		ss, err := seal.ParseSealedSecret(data)
		if err != nil {
			return nil // Not a SealedSecret
		}

		relPath, _ := filepath.Rel(repoPath, path)
		found = append(found, discoveredSecret{
			path:         relPath,
			sealedSecret: ss,
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("walk repo: %w", err)
	}

	if len(found) == 0 {
		fmt.Println("No SealedSecret manifests found.")
		return nil
	}

	fmt.Printf("Found %d SealedSecret manifests:\n\n", len(found))

	// Process each discovered secret
	for _, ds := range found {
		shortName := deriveShortName(ds.sealedSecret.Metadata.Namespace, ds.sealedSecret.Metadata.Name)
		metadataPath := filepath.Join(metadataDir, shortName+".yaml")

		// Check if already registered
		if _, err := os.Stat(metadataPath); err == nil {
			fmt.Printf("  %-30s (already registered)\n", shortName)
			continue
		}

		// Create metadata stub
		stub := generateMetadataStub(ds, shortName)

		if dryRun {
			fmt.Printf("  %-30s [DRY RUN]\n", shortName)
			continue
		}

		if err := os.WriteFile(metadataPath, []byte(stub), 0o644); err != nil {
			return fmt.Errorf("write metadata %s: %w", shortName, err)
		}

		fmt.Printf("  %-30s ✓ created\n", shortName)
	}

	fmt.Printf("\nMetadata stubs written to %s\n", metadataDir)

	if discoverNonInteractive {
		fmt.Println("\nNote: Rotation modes set to 'unknown'. Update metadata to configure rotation.")
	} else {
		fmt.Println("\nRun 'waxseal list' to view registered secrets.")
	}

	return nil
}

type discoveredSecret struct {
	path         string
	sealedSecret *seal.SealedSecret
}

func deriveShortName(namespace, name string) string {
	// Use namespace-name format, sanitizing for filesystem
	short := namespace + "-" + name
	short = strings.ReplaceAll(short, "/", "-")
	short = strings.ReplaceAll(short, "\\", "-")
	return short
}

func generateMetadataStub(ds discoveredSecret, shortName string) string {
	ss := ds.sealedSecret

	var keys strings.Builder
	for _, keyName := range ss.GetEncryptedKeys() {
		keys.WriteString(fmt.Sprintf(`  - keyName: %s
    source:
      kind: gsm
    gsm:
      secretResource: "projects/<PROJECT>/secrets/%s-%s"
      version: "1"
    rotation:
      mode: unknown
`, keyName, shortName, keyName))
	}

	return fmt.Sprintf(`shortName: %s
manifestPath: %s
sealedSecret:
  name: %s
  namespace: %s
  scope: %s
  type: %s
status: active
keys:
%s`, shortName, ds.path, ss.Metadata.Name, ss.Metadata.Namespace, ss.GetScope(), ss.GetSecretType(), keys.String())
}
