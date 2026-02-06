package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/store"
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
var validateCluster bool
var validateGSM bool

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().IntVar(&validateSoonDays, "soon-days", 30, "Days threshold for 'expiring soon' warnings")
	validateCmd.Flags().BoolVar(&validateCluster, "cluster", false, "Compare against live cluster state")
	validateCmd.Flags().BoolVar(&validateGSM, "gsm", false, "Verify GSM secrets exist")
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
			printSuccess("Config valid: %s", configFile)
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

	printSuccess("Validated %d secrets", secretCount)

	// Cluster validation (if --cluster flag set)
	if validateCluster || validateGSM {
		// Load config for GSM
		cfgFile := configPath
		if !filepath.IsAbs(cfgFile) {
			cfgFile = filepath.Join(repoPath, cfgFile)
		}
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		ctx := context.Background()
		var gsmStore *store.GSMStore
		if validateGSM {
			gsmStore, err = store.NewGSMStore(ctx, cfg.Store.ProjectID)
			if err != nil {
				return fmt.Errorf("create GSM store: %w", err)
			}
			defer gsmStore.Close()
		}

		fmt.Println()
		if validateCluster {
			fmt.Println("Checking cluster state...")
		}
		if validateGSM {
			fmt.Println("Checking GSM secrets...")
		}
		fmt.Println()

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}

			path := filepath.Join(metadataDir, entry.Name())
			data, _ := os.ReadFile(path)
			m, err := core.ParseMetadata(data)
			if err != nil {
				continue
			}

			if m.IsRetired() {
				continue
			}

			// Cluster check
			if validateCluster {
				clusterData, err := readSecretFromCluster(ctx, m.SealedSecret.Namespace, m.SealedSecret.Name)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: %s: cannot read from cluster: %v\n", m.ShortName, err)
					hasWarnings = true
				} else {
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
						fmt.Fprintf(os.Stderr, "ERROR: %s: keys in metadata but NOT in cluster: %v\n", m.ShortName, missingInCluster)
						hasErrors = true
					}
					if len(extraInCluster) > 0 {
						fmt.Fprintf(os.Stderr, "WARNING: %s: keys in cluster but NOT in metadata: %v\n", m.ShortName, extraInCluster)
						hasWarnings = true
					}
					if len(missingInCluster) == 0 && len(extraInCluster) == 0 {
						fmt.Printf("  %s✓%s %s: cluster matches metadata (%d keys)\n", styleGreen, styleReset, m.ShortName, len(clusterData))
					}
				}
			}

			// GSM check
			if validateGSM {
				for _, km := range m.Keys {
					if km.GSM != nil {
						exists, _, err := gsmStore.SecretVersionExists(ctx, km.GSM.SecretResource, km.GSM.Version)
						if err != nil {
							fmt.Fprintf(os.Stderr, "WARNING: %s/%s: cannot check GSM: %v\n", m.ShortName, km.KeyName, err)
							hasWarnings = true
						} else if !exists {
							fmt.Fprintf(os.Stderr, "ERROR: %s/%s: GSM secret not found: %s (v%s)\n",
								m.ShortName, km.KeyName, km.GSM.SecretResource, km.GSM.Version)
							hasErrors = true
						}
					}
					if km.Computed != nil && km.Computed.GSM != nil {
						exists, _, err := gsmStore.SecretVersionExists(ctx, km.Computed.GSM.SecretResource, km.Computed.GSM.Version)
						if err != nil {
							fmt.Fprintf(os.Stderr, "WARNING: %s/%s: cannot check computed GSM: %v\n", m.ShortName, km.KeyName, err)
							hasWarnings = true
						} else if !exists {
							fmt.Fprintf(os.Stderr, "ERROR: %s/%s: computed GSM secret not found: %s (v%s)\n",
								m.ShortName, km.KeyName, km.Computed.GSM.SecretResource, km.Computed.GSM.Version)
							hasErrors = true
						}
					}
				}
			}
		}
	}

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
