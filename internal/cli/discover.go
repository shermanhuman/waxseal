package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/config"
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

	// Load config to get project ID
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	var projectID string
	cfg, err := config.Load(configFile)
	if err == nil && cfg.Store.ProjectID != "" {
		projectID = cfg.Store.ProjectID
	}

	// Walk repo and find SealedSecrets
	var found []discoveredSecret
	err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
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

	reader := bufio.NewReader(os.Stdin)

	// Process each discovered secret
	for _, ds := range found {
		shortName := deriveShortName(ds.sealedSecret.Metadata.Namespace, ds.sealedSecret.Metadata.Name)
		metadataPath := filepath.Join(metadataDir, shortName+".yaml")

		// Check if already registered
		if _, err := os.Stat(metadataPath); err == nil {
			fmt.Printf("  %-30s (already registered)\n", shortName)
			continue
		}

		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Secret: %s\n", shortName)
		fmt.Printf("  Namespace: %s\n", ds.sealedSecret.Metadata.Namespace)
		fmt.Printf("  Name:      %s\n", ds.sealedSecret.Metadata.Name)
		fmt.Printf("  Path:      %s\n", ds.path)
		fmt.Printf("  Keys:      %v\n", ds.sealedSecret.GetEncryptedKeys())
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		var stub string
		if discoverNonInteractive {
			stub = generateMetadataStub(ds, shortName, projectID, nil, "", "", "")
		} else {
			// Interactive mode
			description, documentation, owner, keyConfigs, err := runInteractiveWizard(reader, ds, shortName, projectID)
			if err != nil {
				return err
			}
			stub = generateMetadataStub(ds, shortName, projectID, keyConfigs, description, documentation, owner)
		}

		if dryRun {
			fmt.Printf("  [DRY RUN] Would create: %s\n", metadataPath)
			fmt.Println("\n--- Generated metadata ---")
			fmt.Println(stub)
			fmt.Println("---")
			continue
		}

		if err := os.WriteFile(metadataPath, []byte(stub), 0o644); err != nil {
			return fmt.Errorf("write metadata %s: %w", shortName, err)
		}

		fmt.Printf("✓ Created: %s\n", metadataPath)
	}

	fmt.Printf("\nMetadata stubs written to %s\n", metadataDir)

	if discoverNonInteractive {
		fmt.Println("\nNote: Rotation modes set to 'unknown'. Update metadata to configure rotation.")
	} else {
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Run 'waxseal bootstrap <shortName>' to push secrets to GSM")
		fmt.Println("  2. Run 'waxseal list' to view registered secrets")
	}

	return nil
}

type discoveredSecret struct {
	path         string
	sealedSecret *seal.SealedSecret
}

type keyConfig struct {
	keyName    string
	sourceKind string // "gsm" (default) or "computed"

	// GSM fields
	gsmResource  string
	rotationMode string

	// Generator fields (if rotationMode == generated)
	genType   string // randomBase64, randomHex
	genLength string // keep as string for simple input handling

	// Computed fields
	template string

	expiry string
}

func deriveShortName(namespace, name string) string {
	// Use namespace-name format, sanitizing for filesystem
	short := namespace + "-" + name
	short = strings.ReplaceAll(short, "/", "-")
	short = strings.ReplaceAll(short, "\\", "-")
	return short
}

func runInteractiveWizard(reader *bufio.Reader, ds discoveredSecret, shortName, projectID string) (string, string, string, []keyConfig, error) {
	keys := ds.sealedSecret.GetEncryptedKeys()
	configs := make([]keyConfig, 0, len(keys))

	var description, documentation, owner string

	// Ask for project if not configured
	if projectID == "" {
		fmt.Print("GCP Project ID: ")
		input, _ := reader.ReadString('\n')
		projectID = strings.TrimSpace(input)
		if projectID == "" {
			projectID = "<PROJECT>"
		}
	}

	// Secret-level metadata
	fmt.Printf("\nMetadata for %s:\n", shortName)

	fmt.Print("  Description (optional): ")
	input, _ := reader.ReadString('\n')
	description = strings.TrimSpace(input)

	fmt.Print("  Documentation URL (optional): ")
	input, _ = reader.ReadString('\n')
	documentation = strings.TrimSpace(input)

	fmt.Print("  Owner (optional, e.g. team-name): ")
	input, _ = reader.ReadString('\n')
	owner = strings.TrimSpace(input)

	fmt.Println("\nConfigure each key:")
	fmt.Println("  Sources: gsm (default), computed")
	fmt.Println("  Rotation modes: manual, generated, external, unknown")
	fmt.Println()

	for _, keyName := range keys {
		config := keyConfig{keyName: keyName}

		// Source kind
		fmt.Printf("  [%s] Source kind [gsm/computed] (Enter for gsm): ", keyName)
		input, _ = reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "computed" || input == "c" {
			config.sourceKind = "computed"
			fmt.Printf("    Template (e.g. {{.password}}): ")
			tmpl, _ := reader.ReadString('\n')
			config.template = strings.TrimSpace(tmpl)
			fmt.Println("    (Note: You will need to edit the metadata file to map inputs)")
		} else {
			config.sourceKind = "gsm"

			// Generate default GSM resource
			defaultGSM := fmt.Sprintf("projects/%s/secrets/%s-%s", projectID, shortName, sanitizeGSMName(keyName))

			// GSM Resource
			fmt.Printf("    GSM resource (Enter for default):\n")
			fmt.Printf("      Default: %s\n", defaultGSM)
			fmt.Print("      > ")
			input, _ = reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				config.gsmResource = defaultGSM
			} else {
				config.gsmResource = input
			}

			// Rotation mode
			fmt.Printf("    Rotation mode [manual/generated/external/unknown] (Enter for manual): ")
			input, _ = reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))
			switch input {
			case "generated", "g":
				config.rotationMode = "generated"
				fmt.Printf("      Generator type [randomBase64/randomHex] (Enter for randomBase64): ")
				gt, _ := reader.ReadString('\n')
				gt = strings.TrimSpace(gt)
				if gt == "" {
					gt = "randomBase64"
				}
				config.genType = gt

				fmt.Printf("      Length (Enter for 32): ")
				classes, _ := reader.ReadString('\n')
				classes = strings.TrimSpace(classes)
				// reusing var names lazily? No, 'genLength'
				if classes == "" {
					classes = "32"
				}
				config.genLength = classes

			case "external", "e":
				config.rotationMode = "external"

			case "unknown", "u":
				config.rotationMode = "unknown"
			default:
				config.rotationMode = "manual"
			}

			// Expiry (optional)
			fmt.Printf("    Expiry date (YYYY-MM-DD, Enter to skip): ")
			input, _ = reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input != "" {
				if _, err := time.Parse("2006-01-02", input); err == nil {
					config.expiry = input
				} else {
					fmt.Printf("      ⚠ Invalid date format, skipping expiry\n")
				}
			}
		}

		configs = append(configs, config)
		fmt.Println()
	}

	return description, documentation, owner, configs, nil
}

func generateMetadataStub(ds discoveredSecret, shortName, projectID string, keyConfigs []keyConfig, description, documentation, owner string) string {
	ss := ds.sealedSecret

	// If no key configs provided, use defaults (non-interactive mode)
	if keyConfigs == nil {
		keyConfigs = make([]keyConfig, 0)
		for _, keyName := range ss.GetEncryptedKeys() {
			gsmResource := fmt.Sprintf("projects/%s/secrets/%s-%s", projectID, shortName, sanitizeGSMName(keyName))
			if projectID == "" {
				gsmResource = fmt.Sprintf("projects/<PROJECT>/secrets/%s-%s", shortName, sanitizeGSMName(keyName))
			}
			keyConfigs = append(keyConfigs, keyConfig{
				keyName:      keyName,
				sourceKind:   "gsm",
				gsmResource:  gsmResource,
				rotationMode: "unknown",
			})
		}
	}

	var keys strings.Builder
	for _, kc := range keyConfigs {
		// Default source if empty
		if kc.sourceKind == "" {
			kc.sourceKind = "gsm"
		}

		if kc.sourceKind == "computed" {
			keys.WriteString(fmt.Sprintf(`  - keyName: %s
    source:
      kind: computed
    computed:
      kind: template
      template: "%s"
      inputs: [] # TODO: map variables here
`, kc.keyName, kc.template))
		} else {
			// GSM
			keys.WriteString(fmt.Sprintf(`  - keyName: %s
    source:
      kind: gsm
    gsm:
      secretResource: "%s"
      version: "1"
    rotation:
      mode: %s
`, kc.keyName, kc.gsmResource, kc.rotationMode))

			// Generator details
			if kc.rotationMode == "generated" {
				// Defaults
				gt := kc.genType
				if gt == "" {
					gt = "randomBase64"
				}
				gl := kc.genLength
				if gl == "" {
					gl = "32"
				}

				keys.WriteString(fmt.Sprintf(`      generator:
        kind: %s
        chars: %s
`, gt, gl))
			}

			if kc.expiry != "" {
				keys.WriteString(fmt.Sprintf(`    expiry: "%s"
`, kc.expiry))
			}
		}
	}

	var meta strings.Builder
	if description != "" {
		meta.WriteString(fmt.Sprintf("description: \"%s\"\n", description))
	}
	if documentation != "" {
		meta.WriteString(fmt.Sprintf("documentation: \"%s\"\n", documentation))
	}
	if owner != "" {
		meta.WriteString(fmt.Sprintf("owner: \"%s\"\n", owner))
	}

	return fmt.Sprintf(`shortName: %s
manifestPath: %s
%ssealedSecret:
  name: %s
  namespace: %s
  scope: %s
  type: %s
status: active
keys:
%s`, shortName, ds.path, meta.String(), ss.Metadata.Name, ss.Metadata.Namespace, ss.GetScope(), ss.GetSecretType(), keys.String())
}
