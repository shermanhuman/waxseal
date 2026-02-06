package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/logging"
	"github.com/shermanhuman/waxseal/internal/reseal"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
)

var reencryptCmd = &cobra.Command{
	Use:   "reencrypt",
	Short: "Re-encrypt all secrets with fresh cluster certificate",
	Long: `Re-encrypt all SealedSecrets after the cluster's sealing certificate rotates.

This command:
  1. Fetches the latest certificate from the cluster (or uses --new-cert)
  2. Compares the fingerprint to the stored certificate
  3. Re-seals all active secrets with the new certificate
  4. Updates the repo's certificate file

Use this after the SealedSecrets controller regenerates its keys.

Prerequisites:
  - kubectl configured with cluster access (unless --new-cert is provided)
  - All secrets have valid GSM references in metadata

Examples:
  # Fetch cert from cluster and re-encrypt all secrets
  waxseal reencrypt

  # Use a specific new certificate file
  waxseal reencrypt --new-cert /path/to/new-cert.pem

  # Preview what would be done
  waxseal reencrypt --dry-run`,
	RunE: runReencrypt,
}

var (
	reencryptNewCert string
)

func init() {
	rootCmd.AddCommand(reencryptCmd)
	reencryptCmd.Flags().StringVar(&reencryptNewCert, "new-cert", "", "Path to new certificate file (otherwise fetched from cluster)")
}

func runReencrypt(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Get current certificate path
	currentCertPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(currentCertPath) {
		currentCertPath = filepath.Join(repoPath, currentCertPath)
	}

	// Load current certificate fingerprint
	currentSealer, err := seal.NewCertSealerFromFile(currentCertPath)
	if err != nil {
		return fmt.Errorf("load current certificate: %w", err)
	}
	currentFingerprint := currentSealer.GetCertFingerprint()

	// Get new certificate
	var newCertData []byte
	if reencryptNewCert != "" {
		// Use provided certificate file
		newCertData, err = os.ReadFile(reencryptNewCert)
		if err != nil {
			return fmt.Errorf("read new certificate: %w", err)
		}
		fmt.Printf("Using certificate from: %s\n", reencryptNewCert)
	} else {
		// Fetch from cluster
		err = withSpinner("Fetching certificate from cluster...", func() error {
			newCertData, err = fetchCertFromCluster(ctx)
			return err
		})
		if err != nil {
			return fmt.Errorf("fetch certificate from cluster: %w", err)
		}
		printSuccess("Fetched certificate from cluster")
	}

	// Create sealer from new cert to get fingerprint
	newSealer, err := seal.NewCertSealerFromPEM(newCertData)
	if err != nil {
		return fmt.Errorf("parse new certificate: %w", err)
	}
	newFingerprint := newSealer.GetCertFingerprint()

	// Compare fingerprints
	if currentFingerprint == newFingerprint {
		fmt.Println("Certificate has not changed - no re-encryption needed")
		fmt.Printf("Current fingerprint: %s\n", currentFingerprint[:16])
		return nil
	}

	fmt.Printf("Certificate change detected:\n")
	fmt.Printf("  Current: %s...\n", currentFingerprint[:16])
	fmt.Printf("  New:     %s...\n", newFingerprint[:16])
	fmt.Println()

	// Count active secrets
	allSecrets, _ := files.LoadAllMetadataCollectErrors(repoPath)
	var activeCount int
	for _, m := range allSecrets {
		if !m.IsRetired() {
			activeCount++
		}
	}

	fmt.Printf("Will re-encrypt %d active secrets\n", activeCount)

	if dryRun {
		fmt.Println("\n[DRY RUN] Would update certificate and re-encrypt all secrets")
		return nil
	}

	if !yes {
		ok, err := confirm("Proceed with re-encryption?")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Write new certificate to repo
	if err := os.WriteFile(currentCertPath, newCertData, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	printSuccess("Updated certificate at %s", cfg.Cert.RepoCertPath)

	// Create store
	var secretStore store.Store
	if cfg.Store.Kind == "gsm" {
		gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
		if err != nil {
			return fmt.Errorf("create GSM store: %w", err)
		}
		defer gsmStore.Close()
		secretStore = gsmStore
	} else {
		return fmt.Errorf("unsupported store kind: %s", cfg.Store.Kind)
	}

	// Re-seal all secrets with new certificate using kubeseal binary
	kubesealer := seal.NewKubesealSealer(currentCertPath)
	engine := reseal.NewEngine(secretStore, kubesealer, repoPath, false)

	results, err := engine.ResealAll(ctx)
	if err != nil {
		return err
	}

	var successCount, failCount int
	for _, r := range results {
		if r.Error != nil {
			printError("%s: %v", r.ShortName, r.Error)
			failCount++
		} else {
			printSuccess("%s: re-encrypted %d keys", r.ShortName, r.KeysResealed)
			successCount++
		}
	}

	fmt.Println()
	if failCount > 0 {
		printWarning("Re-encrypted %d secrets, %d failed", successCount, failCount)
		logging.Warn("some secrets failed to re-encrypt", "failed", failCount)
		os.Exit(1)
	} else {
		printSuccess("Re-encrypted %d secrets", successCount)
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  1. Review the changes with 'git diff'")
	fmt.Println("  2. Commit the updated certificate and manifests")
	fmt.Println("  3. Push to trigger GitOps sync")

	return nil
}

// fetchCertFromCluster fetches the sealing certificate from the cluster.
// This is a variable to allow test injection.
var fetchCertFromCluster = defaultFetchCertFromCluster

func defaultFetchCertFromCluster(ctx context.Context) ([]byte, error) {
	// kubeseal --fetch-cert
	cmd := exec.CommandContext(ctx, "kubeseal", "--fetch-cert")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("kubeseal --fetch-cert: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("kubeseal --fetch-cert: %w", err)
	}

	return output, nil
}
