package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
)

// ── Shared flags ────────────────────────────────────────────────────────────

var (
	checkWarnDays      int
	checkFailOnWarning bool
)

// ── Parent: waxseal check ──────────────────────────────────────────────────

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Health checks (cert, expiry, metadata, gsm, cluster)",
	Long: `Run all operational health checks.

By default all checks run. Use subcommands to run individual checks:

  waxseal check             Run all checks
  waxseal check cert        Certificate health only
  waxseal check expiry      Secret expiration only
  waxseal check metadata    Config/schema/hygiene validation
  waxseal check gsm         Verify GSM secret versions exist
  waxseal check cluster     Compare metadata vs live cluster keys

Exit codes:
  0 - All checks passed
  1 - Errors found (expired cert, missing secrets, etc.)
  2 - Warnings only (with --fail-on-warning)`,
	RunE: runCheckAll,
}

// ── Subcommand: waxseal check cert ─────────────────────────────────────────

var checkCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Certificate health only",
	Long: `Check the expiry status of the sealing certificate.

Reports:
  - Certificate validity period
  - Days until expiry
  - Warning if expiring soon (default: 30 days)
  - Error if already expired

Examples:
  waxseal check cert
  waxseal check cert --warn-days 90
  waxseal check cert --fail-on-warning`,
	RunE: runCheckCert,
}

// ── Subcommand: waxseal check expiry ───────────────────────────────────────

var checkExpiryCmd = &cobra.Command{
	Use:   "expiry",
	Short: "Secret expiration only",
	Long: `Check secret expiration and rotation due dates.

Reports:
  - Secrets with expired keys
  - Secrets expiring within the warning threshold

Examples:
  waxseal check expiry
  waxseal check expiry --warn-days 90`,
	RunE: runCheckExpiry,
}

// ── Subcommand: waxseal check metadata ─────────────────────────────────────

var checkMetadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Config/schema/hygiene validation",
	Long: `Validate the waxseal configuration and metadata (structural, CI-friendly).

Checks:
  - Config file exists and is valid
  - Metadata files are valid
  - Manifest paths exist
  - GSM versions are numeric (no aliases)
  - Operator hints and computed key hygiene

Examples:
  waxseal check metadata`,
	RunE: runCheckMetadata,
}

// ── Subcommand: waxseal check gsm ──────────────────────────────────────────

var checkGSMCmd = &cobra.Command{
	Use:   "gsm",
	Short: "Verify GSM secret versions exist",
	Long: `Verify that GSM secrets referenced in metadata actually exist.

Requires GSM authentication (ADC or service account).

Examples:
  waxseal check gsm`,
	RunE: runCheckGSM,
}

// ── Subcommand: waxseal check cluster ──────────────────────────────────────

var checkClusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Compare metadata vs live cluster keys",
	Long: `Compare metadata keys against live Kubernetes cluster state.

Reports:
  - Keys in metadata but missing from cluster
  - Keys in cluster but missing from metadata

Requires kubectl configured with cluster access.

Examples:
  waxseal check cluster`,
	RunE: runCheckCluster,
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.AddCommand(checkCertCmd)
	checkCmd.AddCommand(checkExpiryCmd)
	checkCmd.AddCommand(checkMetadataCmd)
	checkCmd.AddCommand(checkGSMCmd)
	checkCmd.AddCommand(checkClusterCmd)

	// Shared flags on the parent (inherited by subcommands)
	checkCmd.PersistentFlags().IntVar(&checkWarnDays, "warn-days", 30, "Days threshold for expiration warnings")
	checkCmd.PersistentFlags().BoolVar(&checkFailOnWarning, "fail-on-warning", false, "Exit with error code 2 on warnings")

	// Preflight: gsm subcommand needs GSM auth, cluster needs kubectl
	addPreflightChecks(checkGSMCmd, authNeeds{gsm: true})
	addPreflightChecks(checkClusterCmd, authNeeds{kubectl: true})
}

// ── Runners ────────────────────────────────────────────────────────────────

// runCheckAll runs every check, reporting a combined summary.
func runCheckAll(cmd *cobra.Command, args []string) error {
	var hasErrors, hasWarnings bool

	// 1. Cert
	certErr, certWarn := doCheckCert()
	hasErrors = hasErrors || certErr
	hasWarnings = hasWarnings || certWarn

	// 2. Expiry
	expErr, expWarn := doCheckExpiry()
	hasErrors = hasErrors || expErr
	hasWarnings = hasWarnings || expWarn

	// 3. Metadata
	metaErr, metaWarn := doCheckMetadata()
	hasErrors = hasErrors || metaErr
	hasWarnings = hasWarnings || metaWarn

	// 4. GSM (best-effort — skip if auth not available)
	if gsmAvailable() {
		gsmErr, gsmWarn := doCheckGSM(cmd.Context())
		hasErrors = hasErrors || gsmErr
		hasWarnings = hasWarnings || gsmWarn
	} else {
		printDim("Skipping GSM check (no credentials)")
	}

	// 5. Cluster (best-effort — skip if kubectl not available)
	if kubectlAvailable() {
		clErr, clWarn := doCheckCluster(cmd.Context())
		hasErrors = hasErrors || clErr
		hasWarnings = hasWarnings || clWarn
	} else {
		printDim("Skipping cluster check (kubectl not available)")
	}

	return exitWithSummary(hasErrors, hasWarnings)
}

func runCheckCert(cmd *cobra.Command, args []string) error {
	hasErrors, hasWarnings := doCheckCert()
	return exitWithSummary(hasErrors, hasWarnings)
}

func runCheckExpiry(cmd *cobra.Command, args []string) error {
	hasErrors, hasWarnings := doCheckExpiry()
	return exitWithSummary(hasErrors, hasWarnings)
}

func runCheckMetadata(cmd *cobra.Command, args []string) error {
	hasErrors, hasWarnings := doCheckMetadata()
	return exitWithSummary(hasErrors, hasWarnings)
}

func runCheckGSM(cmd *cobra.Command, args []string) error {
	hasErrors, hasWarnings := doCheckGSM(cmd.Context())
	return exitWithSummary(hasErrors, hasWarnings)
}

func runCheckCluster(cmd *cobra.Command, args []string) error {
	hasErrors, hasWarnings := doCheckCluster(cmd.Context())
	return exitWithSummary(hasErrors, hasWarnings)
}

// ── Shared logic ───────────────────────────────────────────────────────────

// exitWithSummary prints the check summary and exits with the appropriate code.
func exitWithSummary(hasErrors, hasWarnings bool) error {
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

// ── Check implementations ──────────────────────────────────────────────────

// doCheckCert validates the sealing certificate.
func doCheckCert() (hasErrors, hasWarnings bool) {
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

// doCheckExpiry validates secret expiration and rotation dates.
func doCheckExpiry() (hasErrors, hasWarnings bool) {
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

// doCheckMetadata validates repo structure and metadata consistency.
// This absorbs the former standalone `validate` command.
func doCheckMetadata() (hasErrors, hasWarnings bool) {
	// Check config exists
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ERROR: config not found: %s\n", configFile)
		hasErrors = true
	} else {
		data, err := os.ReadFile(configFile)
		if err != nil {
			printError("Read config: %v", err)
			hasErrors = true
		} else if _, err := parseConfig(data); err != nil {
			printError("Invalid config: %v", err)
			hasErrors = true
		} else {
			printSuccess("Config valid: %s", configFile)
		}
	}

	// Check metadata
	secrets, loadErrs := files.LoadAllMetadataCollectErrors(repoPath)
	if len(secrets) == 0 && len(loadErrs) > 0 {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", loadErrs[0])
		return true, hasWarnings
	}
	for _, err := range loadErrs {
		printError("%v", err)
		hasErrors = true
	}

	var secretCount int
	for _, m := range secrets {
		// Check manifest exists
		manifestPath := m.ManifestPath
		if !filepath.IsAbs(manifestPath) {
			manifestPath = filepath.Join(repoPath, manifestPath)
		}
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			printError("Manifest not found: %s (referenced by %s)", m.ManifestPath, m.ShortName)
			hasErrors = true
		}

		// Validate GSM versions are numeric
		for _, k := range m.Keys {
			if k.GSM != nil {
				if err := validateNumericVersion(k.GSM.Version); err != nil {
					printError("%s/%s: %v", m.ShortName, k.KeyName, err)
					hasErrors = true
				}
			}

			// Hygiene: operatorHints must be GSM-backed
			if k.OperatorHints != nil {
				if k.OperatorHints.GSM == nil {
					printError("%s/%s: operatorHints must have gsm reference (inline hints not allowed)",
						m.ShortName, k.KeyName)
					hasErrors = true
				} else if k.OperatorHints.Format != "json" {
					printWarning("%s/%s: operatorHints.format should be 'json' (got %q)",
						m.ShortName, k.KeyName, k.OperatorHints.Format)
					hasWarnings = true
				}
			}

			// Hygiene: internal hostnames in computed.params
			if k.Computed != nil && len(k.Computed.Params) > 0 {
				for paramName, paramValue := range k.Computed.Params {
					if containsInternalHostname(paramValue) {
						printWarning("%s/%s: computed.params[%s] contains internal hostname pattern",
							m.ShortName, k.KeyName, paramName)
						hasWarnings = true
					}
				}
			}
		}

		secretCount++
	}

	printSuccess("Validated %d secrets", secretCount)
	return hasErrors, hasWarnings
}

// doCheckGSM verifies that GSM secrets referenced in metadata actually exist.
func doCheckGSM(ctx context.Context) (hasErrors, hasWarnings bool) {
	cfg, err := resolveConfig()
	if err != nil {
		printError("Cannot load config: %v", err)
		return true, false
	}

	gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		printError("Cannot create GSM store: %v", err)
		return true, false
	}
	defer gsmStore.Close()

	secrets, _ := files.LoadAllMetadataCollectErrors(repoPath)

	fmt.Println()
	fmt.Println("Checking GSM secrets...")
	fmt.Println()

	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}

		for _, km := range m.Keys {
			if km.GSM != nil {
				exists, _, err := gsmStore.SecretVersionExists(ctx, km.GSM.SecretResource, km.GSM.Version)
				if err != nil {
					printWarning("%s/%s: cannot check GSM: %v", m.ShortName, km.KeyName, err)
					hasWarnings = true
				} else if !exists {
					printError("%s/%s: GSM secret not found: %s (v%s)",
						m.ShortName, km.KeyName, km.GSM.SecretResource, km.GSM.Version)
					hasErrors = true
				}
			}
			if km.Computed != nil && km.Computed.GSM != nil {
				exists, _, err := gsmStore.SecretVersionExists(ctx, km.Computed.GSM.SecretResource, km.Computed.GSM.Version)
				if err != nil {
					printWarning("%s/%s: cannot check computed GSM: %v", m.ShortName, km.KeyName, err)
					hasWarnings = true
				} else if !exists {
					printError("%s/%s: computed GSM secret not found: %s (v%s)",
						m.ShortName, km.KeyName, km.Computed.GSM.SecretResource, km.Computed.GSM.Version)
					hasErrors = true
				}
			}
		}
	}

	return hasErrors, hasWarnings
}

// doCheckCluster compares metadata keys against live Kubernetes cluster.
func doCheckCluster(ctx context.Context) (hasErrors, hasWarnings bool) {
	secrets, _ := files.LoadAllMetadataCollectErrors(repoPath)

	fmt.Println()
	fmt.Println("Checking cluster state...")
	fmt.Println()

	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}

		clusterData, err := readSecretFromCluster(ctx, m.SealedSecret.Namespace, m.SealedSecret.Name)
		if err != nil {
			printWarning("%s: cannot read from cluster: %v", m.ShortName, err)
			hasWarnings = true
			continue
		}

		clusterKeys := make(map[string]bool)
		for k := range clusterData {
			clusterKeys[k] = true
		}

		var missingInCluster []string
		var extraInCluster []string

		for _, km := range m.Keys {
			if !clusterKeys[km.KeyName] {
				missingInCluster = append(missingInCluster, km.KeyName)
			}
		}

		metadataKeys := make(map[string]bool)
		for _, km := range m.Keys {
			metadataKeys[km.KeyName] = true
		}
		for k := range clusterData {
			if !metadataKeys[k] {
				extraInCluster = append(extraInCluster, k)
			}
		}

		if len(missingInCluster) > 0 {
			printError("%s: keys in metadata but NOT in cluster: %v", m.ShortName, missingInCluster)
			hasErrors = true
		}
		if len(extraInCluster) > 0 {
			printWarning("%s: keys in cluster but NOT in metadata: %v", m.ShortName, extraInCluster)
			hasWarnings = true
		}
		if len(missingInCluster) == 0 && len(extraInCluster) == 0 {
			fmt.Printf("  %s✓%s %s: cluster matches metadata (%d keys)\n", styleGreen, styleReset, m.ShortName, len(clusterData))
		}
	}

	return hasErrors, hasWarnings
}

// ── Helpers ────────────────────────────────────────────────────────────────

// gsmAvailable returns true if GSM credentials are likely available.
func gsmAvailable() bool {
	// Check for ADC or GOOGLE_APPLICATION_CREDENTIALS
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	// Check ADC default location
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	adcPath := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	_, err = os.Stat(adcPath)
	return err == nil
}

// kubectlAvailable returns true if kubectl is available in PATH.
func kubectlAvailable() bool {
	_, err := exec.LookPath("kubectl")
	return err == nil
}

// validateNumericVersion checks that a GSM version string is numeric.
func validateNumericVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version is empty")
	}
	for _, c := range version {
		if c < '0' || c > '9' {
			return fmt.Errorf("version %q must be numeric (aliases like 'latest' are not supported)", version)
		}
	}
	return nil
}

// parseConfig performs basic config validation.
func parseConfig(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("config is empty")
	}
	if !strings.Contains(string(data), "version:") {
		return nil, fmt.Errorf("missing version field")
	}
	if !strings.Contains(string(data), "store:") {
		return nil, fmt.Errorf("missing store field")
	}
	return data, nil
}

// containsInternalHostname checks if a value contains patterns suggesting
// internal hostnames that should not be committed to Git.
func containsInternalHostname(value string) bool {
	internalPatterns := []string{
		".internal",
		".local",
		".svc.cluster",
		".corp.",
		"localhost",
		"127.0.0.1",
		"10.0.",
		"172.16.",
		"192.168.",
	}
	lower := strings.ToLower(value)
	for _, pattern := range internalPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
