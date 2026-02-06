package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/reseal"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/state"
	"github.com/spf13/cobra"
)

var resealCmd = &cobra.Command{
	Use:   "reseal [shortName]",
	Short: "Reseal secrets from GSM to SealedSecret manifests",
	Long: `Reseal refreshes the ciphertext in SealedSecret manifests.

This command fetches plaintext values from GSM, evaluates computed keys,
encrypts using the controller's public certificate, and writes the manifest.

When using --all, the command first checks if the cluster's sealing certificate
has rotated. If a rotation is detected, you are prompted to update the repo
certificate and all secrets are re-encrypted.

Examples:
  # Reseal a specific secret
  waxseal reseal my-app-secrets

  # Reseal all active secrets
  waxseal reseal --all

  # Re-encrypt after cert rotation (with new cert from file)
  waxseal reseal --all --new-cert /path/to/new-cert.pem

  # Skip cert check (offline/CI use)
  waxseal reseal --all --skip-cert-check

  # Dry run to see what would be done
  waxseal reseal --all --dry-run

Exit codes:
  0 - Success
  1 - Partial failure (some secrets failed)
  2 - Complete failure`,
	RunE: runReseal,
}

var (
	resealAll           bool
	resealNewCert       string
	resealSkipCertCheck bool
)

func init() {
	rootCmd.AddCommand(resealCmd)
	resealCmd.Flags().BoolVar(&resealAll, "all", false, "Reseal all active secrets")
	resealCmd.Flags().StringVar(&resealNewCert, "new-cert", "", "Path to new certificate file (forces cert update)")
	resealCmd.Flags().BoolVar(&resealSkipCertCheck, "skip-cert-check", false, "Skip cluster cert rotation check (offline/CI)")
	addMetadataCheck(resealCmd)
}

func runReseal(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load config
	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	// Create store
	secretStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	// Create sealer using kubeseal binary for guaranteed controller compatibility
	sealer := resolveSealer(cfg)
	certPath := resolveCertPath(cfg)

	fmt.Printf("Using certificate: %s (kubeseal binary)\n", cfg.Cert.RepoCertPath)

	// Cert rotation check (only on --all or --new-cert)
	if (resealAll || resealNewCert != "") && !resealSkipCertCheck {
		certUpdated, err := checkAndUpdateCert(ctx, certPath)
		if err != nil {
			return err
		}
		if certUpdated {
			// Re-create sealer with new cert
			sealer = resolveSealer(cfg)
		}
	}

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
		printSuccess("%s: would reseal %d keys [DRY RUN]", result.ShortName, result.KeysResealed)
	} else {
		printSuccess("%s: resealed %d keys", result.ShortName, result.KeysResealed)
		// Record in state
		if err := recordResealState(result.ShortName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update state: %v\n", err)
		}
	}

	return nil
}

func runResealAll(ctx context.Context, engine *reseal.Engine) error {
	results, err := engine.ResealAll(ctx)
	if err != nil {
		return err
	}

	var successCount, failCount int
	var successNames []string
	for _, r := range results {
		if r.Error != nil {
			printError("%s: %v", r.ShortName, r.Error)
			failCount++
		} else if r.DryRun {
			printSuccess("%s: would reseal %d keys [DRY RUN]", r.ShortName, r.KeysResealed)
			successCount++
		} else {
			printSuccess("%s: resealed %d keys", r.ShortName, r.KeysResealed)
			successCount++
			successNames = append(successNames, r.ShortName)
		}
	}

	// Batch record successful reseals in state
	if len(successNames) > 0 {
		if err := recordResealStateAll(successNames); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update state: %v\n", err)
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

// recordResealState adds a reseal record to state.yaml.
func recordResealState(shortName string) error {
	return withState(func(s *state.State) {
		s.AddRotation(shortName, "", "reseal", "")
	})
}

// recordResealStateAll records multiple reseals in a single state update.
func recordResealStateAll(shortNames []string) error {
	return withState(func(s *state.State) {
		for _, name := range shortNames {
			s.AddRotation(name, "", "reseal", "")
		}
	})
}

// checkAndUpdateCert checks if the cluster's sealing certificate has rotated
// and updates the repo cert if needed. Returns true if the cert was updated.
func checkAndUpdateCert(ctx context.Context, certPath string) (bool, error) {
	// Load current certificate fingerprint
	currentSealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		// If we can't read the current cert, skip comparison
		fmt.Printf("Note: could not read current cert (%v), skipping cert check\n", err)
		return false, nil
	}
	currentFingerprint := currentSealer.GetCertFingerprint()

	// Get new certificate
	var newCertData []byte
	if resealNewCert != "" {
		newCertData, err = os.ReadFile(resealNewCert)
		if err != nil {
			return false, fmt.Errorf("read new certificate: %w", err)
		}
		fmt.Printf("Using certificate from: %s\n", resealNewCert)
	} else {
		err = withSpinner("Checking cluster certificate...", func() error {
			newCertData, err = fetchCertFromCluster(ctx)
			return err
		})
		if err != nil {
			// Non-fatal: can't reach cluster, continue with current cert
			fmt.Printf("Note: could not fetch cluster cert (%v), using existing\n", err)
			return false, nil
		}
	}

	// Parse new cert for fingerprint
	newSealer, err := seal.NewCertSealerFromPEM(newCertData)
	if err != nil {
		return false, fmt.Errorf("parse new certificate: %w", err)
	}
	newFingerprint := newSealer.GetCertFingerprint()

	// Compare fingerprints
	if currentFingerprint == newFingerprint {
		printSuccess("Certificate unchanged (fingerprint: %s...)", currentFingerprint[:16])
		return false, nil
	}

	fmt.Printf("Certificate rotation detected:\n")
	fmt.Printf("  Current: %s...\n", currentFingerprint[:16])
	fmt.Printf("  New:     %s...\n", newFingerprint[:16])
	fmt.Println()

	// Count active secrets for user context
	allSecrets, _ := files.LoadAllMetadataCollectErrors(repoPath)
	var activeCount int
	for _, m := range allSecrets {
		if !m.IsRetired() {
			activeCount++
		}
	}
	fmt.Printf("Will re-encrypt %d active secrets with new certificate\n", activeCount)

	if dryRun {
		fmt.Println("[DRY RUN] Would update certificate and re-encrypt all secrets")
		return true, nil
	}

	if !yes {
		ok, err := confirm("Update certificate and re-encrypt all secrets?")
		if err != nil {
			return false, err
		}
		if !ok {
			fmt.Println("Continuing with existing certificate.")
			return false, nil
		}
	}

	// Write new certificate
	if err := os.WriteFile(certPath, newCertData, 0o644); err != nil {
		return false, fmt.Errorf("write certificate: %w", err)
	}
	printSuccess("Updated certificate at %s", certPath)
	return true, nil
}

// fetchCertFromCluster fetches the sealing certificate from the cluster.
// This is a variable to allow test injection.
var fetchCertFromCluster = defaultFetchCertFromCluster

func defaultFetchCertFromCluster(ctx context.Context) ([]byte, error) {
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
