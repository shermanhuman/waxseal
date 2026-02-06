package cli

import (
	"fmt"
	"os"

	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check operational health (cert expiry, secret rotation)",
	Long: `Check operational health of certificates and secrets.

Checks:
  - Certificate validity and expiration
  - Secret expiration / rotation due dates

By default all checks run. Use flags to limit scope:
  --cert      Only check certificate
  --expiry    Only check secret expiration

Exit codes:
  0 - All checks passed
  1 - Certificate expired or secrets expired
  2 - Warnings only (with --fail-on-warning)`,
	RunE: runCheck,
}

var (
	checkWarnDays      int
	checkFailOnWarning bool
	checkCertOnly      bool
	checkExpiryOnly    bool
)

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().IntVar(&checkWarnDays, "warn-days", 30, "Days threshold for expiration warnings")
	checkCmd.Flags().BoolVar(&checkFailOnWarning, "fail-on-warning", false, "Exit with error code 2 on warnings")
	checkCmd.Flags().BoolVar(&checkCertOnly, "cert", false, "Only check certificate expiry")
	checkCmd.Flags().BoolVar(&checkExpiryOnly, "expiry", false, "Only check secret expiration")
}

func runCheck(cmd *cobra.Command, args []string) error {
	// If neither flag set, check both
	runCert := !checkCertOnly && !checkExpiryOnly || checkCertOnly
	runExpiry := !checkCertOnly && !checkExpiryOnly || checkExpiryOnly

	var hasErrors bool
	var hasWarnings bool

	if runCert {
		certErrs, certWarns := checkCertExpiry()
		hasErrors = hasErrors || certErrs
		hasWarnings = hasWarnings || certWarns
	}

	if runExpiry {
		expErrs, expWarns := checkSecretExpiry()
		hasErrors = hasErrors || expErrs
		hasWarnings = hasWarnings || expWarns
	}

	// Summary
	if hasErrors {
		fmt.Println("\nCheck failed")
		os.Exit(1)
	}
	if hasWarnings {
		fmt.Println("\nCheck passed with warnings")
		if checkFailOnWarning {
			os.Exit(2)
		}
		return nil
	}

	fmt.Println("\nAll checks passed")
	return nil
}

// checkCertExpiry validates the sealing certificate.
func checkCertExpiry() (hasErrors, hasWarnings bool) {
	cfg, err := resolveConfig()
	if err != nil {
		printError("Cannot load config: %v", err)
		return true, false
	}

	certPath := resolveCertPath(cfg)

	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		printError("Cannot load certificate: %v", err)
		return true, false
	}

	notBefore := sealer.GetCertNotBefore()
	notAfter := sealer.GetCertNotAfter()
	fingerprint := sealer.GetCertFingerprint()
	subject := sealer.GetSubject()
	daysUntil := sealer.DaysUntilExpiry()

	fmt.Printf("Certificate: %s\n", cfg.Cert.RepoCertPath)
	fmt.Printf("Subject:     %s\n", subject)
	fmt.Printf("Fingerprint: %s...\n", fingerprint[:16])
	fmt.Printf("Valid from:  %s\n", notBefore.Format("2006-01-02"))
	fmt.Printf("Valid until: %s\n", notAfter.Format("2006-01-02"))
	fmt.Println()

	if sealer.IsExpired() {
		printError("Certificate EXPIRED (%d days ago)", -daysUntil)
		fmt.Println("\nAction required:")
		fmt.Println("  1. Rotate the SealedSecrets controller certificate")
		fmt.Println("  2. Run 'waxseal reseal --all' to re-encrypt all secrets")
		return true, false
	}

	if sealer.ExpiresWithinDays(checkWarnDays) {
		printWarning("Certificate expiring in %d days", daysUntil)
		fmt.Println("\nRecommended actions:")
		fmt.Println("  1. Plan certificate rotation before expiry")
		fmt.Println("  2. After rotation, run 'waxseal reseal --all'")
		return false, true
	}

	printSuccess("Certificate valid (%d days remaining)", daysUntil)
	return false, false
}

// checkSecretExpiry validates secret expiration and rotation dates.
func checkSecretExpiry() (hasErrors, hasWarnings bool) {
	secrets, loadErrs := files.LoadAllMetadataCollectErrors(repoPath)
	if len(secrets) == 0 && len(loadErrs) > 0 {
		printError("Cannot load metadata: %v", loadErrs[0])
		return true, false
	}
	for _, err := range loadErrs {
		printError("Metadata load: %v", err)
		hasErrors = true
	}

	fmt.Println()
	var checked int
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}

		if m.IsExpired() {
			printError("%s: has expired keys", m.ShortName)
			hasErrors = true
		} else if m.ExpiresWithinDays(checkWarnDays) {
			printWarning("%s: keys expiring within %d days", m.ShortName, checkWarnDays)
			hasWarnings = true
		}

		checked++
	}

	if !hasErrors && !hasWarnings {
		printSuccess("No expiring secrets (%d checked)", checked)
	} else {
		fmt.Printf("Checked %d secrets\n", checked)
	}

	return hasErrors, hasWarnings
}
