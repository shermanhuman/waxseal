package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/reseal"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
)

var resealCmd = &cobra.Command{
	Use:   "reseal [shortName]",
	Short: "Reseal secrets from GSM to SealedSecret manifests",
	Long: `Reseal refreshes the ciphertext in SealedSecret manifests.

This command fetches plaintext values from GSM, evaluates computed keys,
encrypts using the controller's public certificate, and writes the manifest.

Examples:
  # Reseal a specific secret
  waxseal reseal my-app-secrets

  # Reseal all active secrets
  waxseal reseal --all

  # Dry run to see what would be done
  waxseal reseal --all --dry-run

Exit codes:
  0 - Success
  1 - Partial failure (some secrets failed)
  2 - Complete failure`,
	RunE: runReseal,
}

var resealAll bool

func init() {
	rootCmd.AddCommand(resealCmd)
	resealCmd.Flags().BoolVar(&resealAll, "all", false, "Reseal all active secrets")
	addMetadataCheck(resealCmd)
}

func runReseal(cmd *cobra.Command, args []string) error {
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

	// Create sealer
	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}

	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	fmt.Printf("Using certificate: %s (fingerprint: %s...)\n", cfg.Cert.RepoCertPath, sealer.GetCertFingerprint()[:16])

	// Create engine
	engine := reseal.NewEngine(secretStore, sealer, repoPath, dryRun)

	if resealAll {
		return runResealAll(ctx, engine)
	}

	if len(args) == 0 {
		return fmt.Errorf("specify a secret name or use --all")
	}

	return runResealOne(ctx, engine, args[0])
}

func runResealOne(ctx context.Context, engine *reseal.Engine, shortName string) error {
	result, err := engine.ResealOne(ctx, shortName)
	if err != nil {
		return err
	}

	if result.DryRun {
		fmt.Printf("✓ %s: would reseal %d keys [DRY RUN]\n", result.ShortName, result.KeysResealed)
	} else {
		fmt.Printf("✓ %s: resealed %d keys\n", result.ShortName, result.KeysResealed)
	}

	return nil
}

func runResealAll(ctx context.Context, engine *reseal.Engine) error {
	results, err := engine.ResealAll(ctx)
	if err != nil {
		return err
	}

	var successCount, failCount int
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", r.ShortName, r.Error)
			failCount++
		} else if r.DryRun {
			fmt.Printf("✓ %s: would reseal %d keys [DRY RUN]\n", r.ShortName, r.KeysResealed)
			successCount++
		} else {
			fmt.Printf("✓ %s: resealed %d keys\n", r.ShortName, r.KeysResealed)
			successCount++
		}
	}

	fmt.Printf("\nResealed %d secrets", successCount)
	if failCount > 0 {
		fmt.Printf(", %d failed", failCount)
	}
	fmt.Println()

	if failCount > 0 {
		if successCount > 0 {
			os.Exit(1) // Partial failure
		}
		os.Exit(2) // Complete failure
	}

	return nil
}
