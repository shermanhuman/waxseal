package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
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
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Step 5/7: Key Configuration")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Printf("Configure metadata for %d new secret(s)\n\n", len(newSecrets))
	fmt.Println("For each secret, waxseal needs to know:")
	fmt.Println("  • How each key value is rotated (generated, external, or unknown)")
	fmt.Println("  • Whether any keys are templated (composed from other values)")
	fmt.Println()
	fmt.Println("This metadata enables waxseal to:")
	fmt.Println("  • Automatically re-seal secrets when certificates change")
	fmt.Println("  • Guide you through rotation with the correct steps")
	fmt.Println("  • Track expiration dates and send reminders")
	fmt.Println()

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

	// External rotation fields (if rotationMode == external)
	rotationURL string // URL for rotation portal/docs

	// Templated fields
	template string

	// Expiry
	expiry string
}

func deriveShortName(namespace, name string) string {
	// Use namespace-name format, sanitizing for filesystem
	short := namespace + "-" + name
	short = strings.ReplaceAll(short, "/", "-")
	short = strings.ReplaceAll(short, "\\", "-")
	return short
}

// fetchSecretFromCluster retrieves a secret's data from the Kubernetes cluster
func fetchSecretFromCluster(namespace, name string) (map[string]string, error) {
	cmd := exec.Command("kubectl", "get", "secret", name,
		"-n", namespace, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(output, &secret); err != nil {
		return nil, err
	}

	// Decode base64 values
	result := make(map[string]string)
	for k, v := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			continue
		}
		result[k] = string(decoded)
	}
	return result, nil
}

// detectConnectionStringTemplate analyzes a value and suggests a template if it looks like a connection string
func detectConnectionStringTemplate(value string, allKeys []string) (isTemplate bool, template string) {
	// Check if it looks like a URL-based connection string
	if !strings.Contains(value, "://") {
		return false, ""
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return false, ""
	}

	// Common database/service connection string schemes
	schemes := []string{
		// SQL Databases
		"postgresql", "postgres", "mysql", "mariadb", "sqlserver", "mssql",
		// NoSQL Databases
		"mongodb", "mongodb+srv", "couchbase", "couchdb", "cockroachdb",
		// Key-Value / Cache
		"redis", "rediss", "memcached",
		// Message Queues
		"amqp", "amqps", "nats", "tls", "kafka",
		// Search
		"elasticsearch", "opensearch",
		// Other
		"clickhouse", "cassandra", "scylla", "neo4j", "bolt",
	}
	isDBConnection := false
	for _, s := range schemes {
		if strings.EqualFold(parsed.Scheme, s) {
			isDBConnection = true
			break
		}
	}
	if !isDBConnection {
		return false, ""
	}

	// Build template by replacing user/pass with variables
	template = value
	if parsed.User != nil {
		if username := parsed.User.Username(); username != "" {
			template = strings.Replace(template, username, "{{username}}", 1)
		}
		if password, ok := parsed.User.Password(); ok && password != "" {
			template = strings.Replace(template, password, "{{password}}", 1)
		}
	}

	// Also replace host/port if they match other key names
	hostPort := parsed.Host
	if hostPort != "" {
		// Check if any key contains this host (don't replace - it's likely config, not secret)
	}

	return true, template
}

// suggestKeyType analyzes a key's value and suggests if it should be templated
func suggestKeyType(keyName string, value string, allKeys []string) (suggestedType string, suggestedTemplate string) {
	// Check for common templated key names
	templateKeyPatterns := []string{"url", "uri", "connection", "dsn"}
	keyLower := strings.ToLower(keyName)
	mightBeTemplated := false
	for _, pattern := range templateKeyPatterns {
		if strings.Contains(keyLower, pattern) {
			mightBeTemplated = true
			break
		}
	}

	if !mightBeTemplated {
		return "standalone", ""
	}

	// Try to detect if it's a connection string
	isTemplate, template := detectConnectionStringTemplate(value, allKeys)
	if isTemplate {
		return "templated", template
	}

	return "standalone", ""
}

func runInteractiveWizard(ds discoveredSecret, shortName, projectID string) ([]keyConfig, error) {
	keys := ds.sealedSecret.GetEncryptedKeys()
	configs := make([]keyConfig, 0, len(keys))

	// Try to fetch actual secret values from cluster for template detection
	namespace := ds.sealedSecret.Metadata.Namespace
	name := ds.sealedSecret.Metadata.Name
	secretData, fetchErr := fetchSecretFromCluster(namespace, name)
	if fetchErr != nil {
		// Not a fatal error - just won't have auto-detection
		secretData = nil
	}

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
	// ANSI codes for formatting
	green := "\033[32m"
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"
	clearScreen := "\033[H\033[2J" // Move to top-left and clear screen

	// Pause to let user read the info before clearing screen for forms
	fmt.Println()
	fmt.Print("Press Enter to start configuring secrets...")
	fmt.Scanln()

	// Configure each key
	for i, keyName := range keys {
		config := keyConfig{keyName: keyName}

		// Clear screen and show progress header for this key
		fmt.Print(clearScreen)
		fmt.Printf("🔑 Configuring keys for this secret (%d/%d):\n\n", i+1, len(keys))

		// Show all keys with status
		for j, k := range keys {
			if j < i {
				// Completed
				mode := configs[j].rotationMode
				if configs[j].sourceKind == "templated" {
					mode = "templated"
				}
				fmt.Printf("  %s✓%s %s %s[%s]%s\n", green, reset, k, dim, mode, reset)
			} else if j == i {
				// Current - highlighted
				fmt.Printf("  %s▶ %s%s\n", bold, k, reset)
			} else {
				// Pending
				fmt.Printf("  %s  %s%s\n", dim, k, reset)
			}
		}
		fmt.Println()

		// Generate default GSM resource using manifest filename + secret name
		manifestBase := strings.TrimSuffix(filepath.Base(ds.path), filepath.Ext(ds.path))
		defaultGSM := fmt.Sprintf("projects/%s/secrets/%s-%s", projectID, manifestBase, sanitizeGSMName(keyName))

		// Auto-detect if this looks like a templated key
		var keyType, rotationURL, expiry, template string
		keyType = "standalone" // default
		if secretData != nil {
			if value, ok := secretData[keyName]; ok {
				suggestedType, suggestedTemplate := suggestKeyType(keyName, value, keys)
				keyType = suggestedType
				template = suggestedTemplate
				if suggestedType == "templated" && suggestedTemplate != "" {
					fmt.Printf("💡 Auto-detected: this looks like a connection string\n")
					fmt.Printf("   Suggested template: %s\n\n", suggestedTemplate)
				}
			}
		}

		// All fields on one form
		err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Key type").
					Description("Most keys are standalone values stored in GSM").
					Options(
						huh.NewOption("Standalone - a single value stored in GSM", "standalone"),
						huh.NewOption("Templated - composed from other values (e.g., DATABASE_URL)", "templated"),
					).
					Value(&keyType),
				huh.NewSelect[string]().
					Title("Rotation mode").
					Description("How is this key rotated? (skip for templated keys)").
					Options(
						huh.NewOption("Unknown - I'm not sure yet", "unknown"),
						huh.NewOption("Static - this key cannot be rotated", "static"),
						huh.NewOption("Generated - waxseal auto-rotates (tokens, passwords)", "generated"),
						huh.NewOption("External - managed by you (API portal, vendor)", "external"),
					).
					Value(&config.rotationMode),
				huh.NewInput().
					Title("Rotation URL (optional)").
					Description("Link to rotate this key").
					Placeholder("https://...").
					Value(&rotationURL),
				huh.NewInput().
					Title("Expiry date (optional)").
					Description("When does this key expire?").
					Placeholder("YYYY-MM-DD").
					Value(&expiry),
				huh.NewInput().
					Title("Template (if templated)").
					Description("Use {{varName}} for variables, leave blank if standalone").
					Placeholder("postgresql://{{user}}:{{pass}}@{{host}}/{{db}}").
					Value(&template),
			).Title(fmt.Sprintf("Configure '%s'", keyName)),
		).Run()
		if err != nil {
			return nil, err
		}

		// Set config based on form values
		if keyType == "templated" {
			config.sourceKind = "templated"
			config.template = template
		} else {
			config.sourceKind = "gsm"
			config.gsmResource = defaultGSM
			config.rotationURL = rotationURL
			config.expiry = expiry
		}

		// If generated (for any key type), ask for generator type
		// For templated keys, this configures how the template's input variable is generated
		if config.rotationMode == "generated" {
			err := huh.NewSelect[string]().
				Title("Generator type").
				Description("How should the secret value be generated?").
				Options(
					huh.NewOption("Random Base64 (URL-safe, good for tokens/passwords)", "randomBase64"),
					huh.NewOption("Random Hex (hexadecimal string)", "randomHex"),
				).
				Value(&config.genType).
				Run()
			if err != nil {
				return nil, err
			}
			config.genLength = "32"
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

			// Rotation URL for external keys
			if kc.rotationURL != "" {
				keys.WriteString(fmt.Sprintf(`    operatorHints:
      rotationURL: "%s"
`, kc.rotationURL))
			}

			// Expiry date
			if kc.expiry != "" {
				keys.WriteString(fmt.Sprintf(`    expiry:
      expiresAt: "%sT00:00:00Z"
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
