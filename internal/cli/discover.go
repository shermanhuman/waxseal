package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
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

		// Skip hidden directories (.waxseal, .git, etc.) but not "." or ".."
		if info.IsDir() {
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") && base != "." && base != ".." {
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

	// Separate new vs already-registered secrets
	var newSecrets []discoveredSecret
	var shortNames []string

	// Process each discovered secret to categorize
	for _, ds := range found {
		shortName := deriveShortName(ds.sealedSecret.Metadata.Namespace, ds.sealedSecret.Metadata.Name)
		metadataPath := filepath.Join(metadataDir, shortName+".yaml")

		// Skip already registered
		if _, err := os.Stat(metadataPath); err == nil {
			continue
		}
		newSecrets = append(newSecrets, ds)
		shortNames = append(shortNames, shortName)
	}

	// Show what we found
	if len(found) == 0 {
		fmt.Println("No SealedSecret manifests found.")
		return nil
	}

	// ANSI color codes
	green := "\033[32m"
	reset := "\033[0m"

	fmt.Printf("\n📦 Found %d SealedSecret manifest(s):\n\n", len(found))
	for _, ds := range found {
		shortName := deriveShortName(ds.sealedSecret.Metadata.Namespace, ds.sealedSecret.Metadata.Name)
		metadataPath := filepath.Join(metadataDir, shortName+".yaml")
		if _, err := os.Stat(metadataPath); err == nil {
			fmt.Printf("  %s✓%s %-45s %s[registered]%s\n", green, reset, shortName, green, reset)
		} else {
			fmt.Printf("  %s✓%s %-45s %s[new]%s\n", green, reset, shortName, green, reset)
		}
		fmt.Printf("      %s\n", ds.path)
	}

	if len(newSecrets) == 0 {
		fmt.Println("All discovered secrets are already registered.")
		return nil
	}

	// Explain next steps
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n🔧 Next: Configure metadata for %d new secret(s)\n\n", len(newSecrets))
	fmt.Println("For each secret, waxseal needs to know:")
	fmt.Println("  • How each key value is rotated (generated, external, or unknown)")
	fmt.Println("  • Whether any keys are templated (composed from other values)")
	fmt.Println("")
	fmt.Println("This metadata enables waxseal to:")
	fmt.Println("  • Automatically re-seal secrets when certificates change")
	fmt.Println("  • Guide you through rotation with the correct steps")
	fmt.Println("  • Track expiration dates and send reminders")
	fmt.Println("")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Process each new secret
	for i, ds := range newSecrets {
		shortName := shortNames[i]
		metadataPath := filepath.Join(metadataDir, shortName+".yaml")

		fmt.Printf("\n📋 Configuring: %s (%d/%d)\n", shortName, i+1, len(newSecrets))

		var stub string
		if discoverNonInteractive {
			stub = generateMetadataStub(ds, shortName, projectID, nil)
		} else {
			// Interactive mode
			keyConfigs, err := runInteractiveWizard(ds, shortName, projectID)
			if err != nil {
				return err
			}
			stub = generateMetadataStub(ds, shortName, projectID, keyConfigs)
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
	sourceKind string // "gsm" (default) or "templated"

	// GSM fields
	gsmResource  string
	rotationMode string

	// Generator fields (if rotationMode == generated)
	genType   string // randomBase64, randomHex
	genLength string // keep as string for simple input handling

	// Templated fields
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

func runInteractiveWizard(ds discoveredSecret, shortName, projectID string) ([]keyConfig, error) {
	keys := ds.sealedSecret.GetEncryptedKeys()
	configs := make([]keyConfig, 0, len(keys))

	// Ask for project if not configured
	if projectID == "" {
		err := huh.NewInput().
			Title("GCP Project ID").
			Description("The GCP project where your secrets are stored").
			Placeholder("<PROJECT>").
			Value(&projectID).
			Run()
		if err != nil {
			return nil, err
		}
		if projectID == "" {
			projectID = "<PROJECT>"
		}
	}

	// Configure each key
	fmt.Printf("\n🔑 Configuring %d key(s):\n", len(keys))

	for _, keyName := range keys {
		config := keyConfig{keyName: keyName}

		fmt.Printf("\n  Key: %s\n", keyName)

		// Is this key templated (composed from other values)?
		var isTemplated bool
		err := huh.NewConfirm().
			Title("Is this key templated?").
			Description("Templated keys are composed from other values using a template\n(e.g., a DATABASE_URL built from username, password, host, port)").
			Affirmative("Yes, it's templated").
			Negative("No, it's a standalone value").
			Value(&isTemplated).
			Run()
		if err != nil {
			return nil, err
		}

		if isTemplated {
			config.sourceKind = "templated"
			var template string
			err := huh.NewInput().
				Title("Template").
				Description("Use {{varName}} for variables (e.g., postgresql://{{username}}:{{password}}@{{host}}/{{db}})").
				Placeholder("postgresql://{{username}}:{{password}}@{{host}}:{{port}}/{{db}}").
				Value(&template).
				Run()
			if err != nil {
				return nil, err
			}
			config.template = template
			fmt.Println("    ℹ️  Edit the metadata file to map template inputs to other keys")
		} else {
			config.sourceKind = "gsm"

			// Generate default GSM resource using manifest filename + secret name
			manifestBase := strings.TrimSuffix(filepath.Base(ds.path), filepath.Ext(ds.path))
			defaultGSM := fmt.Sprintf("projects/%s/secrets/%s-%s", projectID, manifestBase, sanitizeGSMName(keyName))
			config.gsmResource = defaultGSM

			// Rotation mode
			err := huh.NewSelect[string]().
				Title("How is this key rotated?").
				Description("Generated keys can be auto-rotated by waxseal.\nExternal keys can link to rotation URLs to guide you through the process.").
				Options(
					huh.NewOption("Unknown - I'm not sure yet (safe default)", "unknown"),
					huh.NewOption("Generated - waxseal can auto-rotate (random bytes, tokens, passwords)", "generated"),
					huh.NewOption("External - managed outside waxseal (API portal, vendor, user/operator)", "external"),
				).
				Value(&config.rotationMode).
				Run()
			if err != nil {
				return nil, err
			}

			// If generated, ask for generator config
			if config.rotationMode == "generated" {
				err := huh.NewSelect[string]().
					Title("Generator type").
					Options(
						huh.NewOption("Random Base64 (URL-safe, good for tokens)", "randomBase64"),
						huh.NewOption("Random Hex (hexadecimal string)", "randomHex"),
					).
					Value(&config.genType).
					Run()
				if err != nil {
					return nil, err
				}
				config.genLength = "32" // Default length
			}
		}

		configs = append(configs, config)
	}

	return configs, nil
}

func generateMetadataStub(ds discoveredSecret, shortName, projectID string, keyConfigs []keyConfig) string {
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

		if kc.sourceKind == "templated" {
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
