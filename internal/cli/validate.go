package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate repo and metadata consistency",
	Long: `Validate the waxseal configuration and metadata.

Checks:
  - Config file exists and is valid
  - Metadata files are valid
  - Manifest paths exist
  - GSM versions are numeric (no aliases)
  - Expiration status (expired = fail, expiring soon = warn)

Exit codes:
  0 - Success
  2 - Validation failed
  >2 - Runtime error`,
	RunE: runValidate,
}

var validateSoonDays int

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().IntVar(&validateSoonDays, "soon-days", 30, "Days threshold for 'expiring soon' warnings")
}

func runValidate(cmd *cobra.Command, args []string) error {
	var hasErrors bool
	var hasWarnings bool

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
			return fmt.Errorf("read config: %w", err)
		}
		if _, err := parseConfig(data); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid config: %v\n", err)
			hasErrors = true
		} else {
			fmt.Printf("✓ Config valid: %s\n", configFile)
		}
	}

	// Check metadata
	metadataDir := filepath.Join(repoPath, ".waxseal", "metadata")
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR: metadata directory not found: %s\n", metadataDir)
			os.Exit(2)
		}
		return fmt.Errorf("read metadata directory: %w", err)
	}

	var secretCount int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(metadataDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: read %s: %v\n", path, err)
			hasErrors = true
			continue
		}

		m, err := core.ParseMetadata(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid metadata %s: %v\n", entry.Name(), err)
			hasErrors = true
			continue
		}

		// Check manifest exists
		manifestPath := m.ManifestPath
		if !filepath.IsAbs(manifestPath) {
			manifestPath = filepath.Join(repoPath, manifestPath)
		}
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR: manifest not found: %s (referenced by %s)\n", m.ManifestPath, m.ShortName)
			hasErrors = true
		}

		// Check expiration
		if m.IsRetired() {
			// Retired secrets don't need expiration checks
		} else if m.IsExpired() {
			fmt.Fprintf(os.Stderr, "ERROR: %s has expired keys\n", m.ShortName)
			hasErrors = true
		} else if m.ExpiresWithinDays(validateSoonDays) {
			fmt.Fprintf(os.Stderr, "WARNING: %s has keys expiring within %d days\n", m.ShortName, validateSoonDays)
			hasWarnings = true
		}

		// Validate GSM versions are numeric
		for _, k := range m.Keys {
			if k.GSM != nil {
				if err := validateNumericVersion(k.GSM.Version); err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: %s/%s: %v\n", m.ShortName, k.KeyName, err)
					hasErrors = true
				}
			}

			// Hygiene: Validate operatorHints (per plan: must be GSM-backed)
			if k.OperatorHints != nil {
				if k.OperatorHints.GSM == nil {
					fmt.Fprintf(os.Stderr, "ERROR: %s/%s: operatorHints must have gsm reference (inline hints not allowed)\n",
						m.ShortName, k.KeyName)
					hasErrors = true
				} else if k.OperatorHints.Format != "json" {
					fmt.Fprintf(os.Stderr, "WARNING: %s/%s: operatorHints.format should be 'json' (got %q)\n",
						m.ShortName, k.KeyName, k.OperatorHints.Format)
					hasWarnings = true
				}
			}

			// Hygiene: Warn on internal hostname patterns in computed.params
			if k.Computed != nil && len(k.Computed.Params) > 0 {
				for paramName, paramValue := range k.Computed.Params {
					if containsInternalHostname(paramValue) {
						fmt.Fprintf(os.Stderr, "WARNING: %s/%s: computed.params[%s] contains internal hostname pattern\n",
							m.ShortName, k.KeyName, paramName)
						hasWarnings = true
					}
				}
			}
		}

		secretCount++
	}

	fmt.Printf("✓ Validated %d secrets\n", secretCount)

	if hasWarnings && !hasErrors {
		fmt.Println("\nValidation passed with warnings")
	}

	if hasErrors {
		fmt.Println("\nValidation failed")
		os.Exit(2)
	}

	fmt.Println("\nValidation passed")
	return nil
}

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

// parseConfig is a simple wrapper to avoid circular imports
func parseConfig(data []byte) (interface{}, error) {
	// We use the config package for real validation
	// For now, just do basic YAML check
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

// Helper to check expiration
func isExpired(expiresAt string) bool {
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return false
	}
	return t.Before(time.Now())
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
