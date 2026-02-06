package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/spf13/cobra"
)

var certCheckCmd = &cobra.Command{
	Use:   "cert-check",
	Short: "Check sealing certificate expiry",
	Long: `Check the expiry status of the sealing certificate.

Reports:
  - Certificate validity period
  - Days until expiry
  - Warning if expiring soon (default: 30 days)
  - Error if already expired

Use this in CI/CD pipelines to catch expiring certificates.

Examples:
  # Check certificate expiry
  waxseal cert-check

  # Warn if expiring within 90 days
  waxseal cert-check --warn-days 90

  # Exit with error if expiring soon (for CI)
  waxseal cert-check --fail-on-warning

Exit codes:
  0 - Certificate is valid and not expiring soon
  1 - Certificate is expired
  2 - Certificate expires within warning threshold (with --fail-on-warning)`,
	RunE: runCertCheck,
}

var (
	certCheckWarnDays      int
	certCheckFailOnWarning bool
)

func init() {
	rootCmd.AddCommand(certCheckCmd)
	certCheckCmd.Flags().IntVar(&certCheckWarnDays, "warn-days", 30, "Warn if certificate expires within this many days")
	certCheckCmd.Flags().BoolVar(&certCheckFailOnWarning, "fail-on-warning", false, "Exit with error code 2 if certificate is expiring soon")
}

func runCertCheck(cmd *cobra.Command, args []string) error {
	// Load config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Get certificate path
	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}

	// Load certificate
	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	// Get certificate info
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

	// Check status
	if sealer.IsExpired() {
		fmt.Println("❌ EXPIRED")
		fmt.Printf("Certificate expired %d days ago\n", -daysUntil)
		fmt.Println("\nAction required:")
		fmt.Println("  1. Rotate the SealedSecrets controller certificate")
		fmt.Println("  2. Run 'waxseal reencrypt' to re-encrypt all secrets")
		os.Exit(1)
	}

	if sealer.ExpiresWithinDays(certCheckWarnDays) {
		printWarning("EXPIRING SOON")
		fmt.Printf("Certificate expires in %d days\n", daysUntil)
		fmt.Println("\nRecommended actions:")
		fmt.Println("  1. Plan certificate rotation before expiry")
		fmt.Println("  2. After rotation, run 'waxseal reencrypt'")

		if certCheckFailOnWarning {
			os.Exit(2)
		}
		return nil
	}

	printSuccess("VALID")
	fmt.Printf("Certificate is valid for %d more days\n", daysUntil)
	return nil
}
