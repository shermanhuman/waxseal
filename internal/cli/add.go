package cli

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add <shortName>",
	Short: "Create a new secret",
	Long: `Create a new secret with metadata, GSM entries, and SealedSecret manifest.

This command:
  1. Creates metadata in .waxseal/metadata/
  2. Creates GSM secrets for each key
  3. Generates a SealedSecret manifest

When --key flags are provided, the command uses flag values for everything
except static key values, which are prompted for securely (never in shell
history). Without --key flags, an interactive TUI wizard collects all input.

Key formats:
  --key=name             Static key (prompts for value securely)
  --key=name:random      Generated random value (mode: generated)

Examples:
  # Interactive mode (no --key flags)
  waxseal add my-app-secrets

  # Mix of static and generated keys (prompts for username value)
  waxseal add my-app-secrets \
    --namespace=default \
    --key=username \
    --key=password:random \
    --key=encryption_key:random \
    --manifest-path=apps/my-app/sealed-secret.yaml

  # All generated keys with custom random length
  waxseal add my-app-secrets \
    --namespace=default \
    --key=api_key:random \
    --key=db_password:random \
    --random-length=64`,
	Args: cobra.ExactArgs(1),
	RunE: runAdd,
}

var (
	addNamespace    string
	addKeys         []string
	addManifestPath string
	addScope        string
	addSecretType   string
	addRandomLength int
)

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVar(&addNamespace, "namespace", "", "Kubernetes namespace")
	addCmd.Flags().StringSliceVar(&addKeys, "key", nil, "Key name (use name:random to auto-generate)")
	addCmd.Flags().StringVar(&addManifestPath, "manifest-path", "", "Path for SealedSecret manifest")
	addCmd.Flags().StringVar(&addScope, "scope", "strict", "Sealing scope (strict, namespace-wide, cluster-wide)")
	addCmd.Flags().StringVar(&addSecretType, "type", "Opaque", "Secret type (Opaque, kubernetes.io/tls, etc.)")
	addCmd.Flags().IntVar(&addRandomLength, "random-length", 32, "Length of generated random values (bytes)")
}

func runAdd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shortName := args[0]

	// Check if already exists
	metadataPath := filepath.Join(repoPath, ".waxseal", "metadata", shortName+".yaml")
	if _, err := os.Stat(metadataPath); err == nil {
		return fmt.Errorf("secret %q already exists", shortName)
	}

	// Load config for project ID
	cfgFile := configPath
	if !filepath.IsAbs(cfgFile) {
		cfgFile = filepath.Join(repoPath, cfgFile)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config (run 'waxseal setup' first): %w", err)
	}

	// Collect input (interactive or flags)
	var namespace, manifestPath, scope, secretType string
	var keys []addKeyInput

	if len(addKeys) > 0 {
		// Non-interactive: --key flags provide all input
		if addNamespace == "" {
			return fmt.Errorf("--namespace is required when using --key flags")
		}

		namespace = addNamespace
		scope = addScope
		secretType = addSecretType
		manifestPath = addManifestPath
		if manifestPath == "" {
			manifestPath = fmt.Sprintf("apps/%s/sealed-secret.yaml", shortName)
		}

		// Parse keys: name:random (generated) or name (static, prompts for value)
		for _, k := range addKeys {
			var keyName string
			var value []byte
			var rotationMode string
			var generator *core.GeneratorConfig

			if parts := strings.SplitN(k, ":", 2); len(parts) > 1 && parts[1] == "random" {
				// name:random → generated key
				keyName = parts[0]
				var err error
				value, err = generateRandomBytes(addRandomLength)
				if err != nil {
					return fmt.Errorf("generate value for key %q: %w", keyName, err)
				}
				rotationMode = "generated"
				generator = &core.GeneratorConfig{Kind: "randomBase64", Bytes: addRandomLength}
			} else {
				// name → static key, prompt for value securely
				keyName = k
				var inputValue string
				err := huh.NewInput().
					Title(fmt.Sprintf("Enter value for key %q", keyName)).
					EchoMode(huh.EchoModePassword).
					Value(&inputValue).
					Run()
				if err != nil {
					return fmt.Errorf("prompt for key %q: %w", keyName, err)
				}
				if inputValue == "" {
					return fmt.Errorf("value for key %q cannot be empty", keyName)
				}
				value = []byte(inputValue)
				rotationMode = "static"
			}

			if keyName == "" {
				return fmt.Errorf("key name cannot be empty in %q", k)
			}

			keys = append(keys, addKeyInput{
				keyName:      keyName,
				value:        value,
				rotationMode: rotationMode,
				generator:    generator,
			})
		}
	} else {
		// Interactive mode
		var err error
		namespace, manifestPath, scope, secretType, keys, err = runAddInteractive(shortName, cfg.Store.ProjectID)
		if err != nil {
			return err
		}
	}

	// Generate GSM resource paths
	type keyToCreate struct {
		keyName     string
		value       []byte
		gsmResource string
	}
	var keysToCreate []keyToCreate
	for _, k := range keys {
		gsmResource := fmt.Sprintf("projects/%s/secrets/%s-%s",
			cfg.Store.ProjectID, shortName, sanitizeGSMName(k.keyName))
		keysToCreate = append(keysToCreate, keyToCreate{
			keyName:     k.keyName,
			value:       k.value,
			gsmResource: gsmResource,
		})
	}

	// Show summary
	fmt.Println()
	fmt.Printf("Creating secret: %s\n", shortName)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  Namespace:    %s\n", namespace)
	fmt.Printf("  Manifest:     %s\n", manifestPath)
	fmt.Printf("  Scope:        %s\n", scope)
	fmt.Printf("  Keys:         %d\n", len(keysToCreate))
	for _, k := range keysToCreate {
		fmt.Printf("    • %s → %s\n", k.keyName, k.gsmResource)
	}
	fmt.Println()

	if dryRun {
		fmt.Println("[DRY RUN] Would create:")
		fmt.Printf("  - %s\n", metadataPath)
		fmt.Printf("  - %s\n", filepath.Join(repoPath, manifestPath))
		fmt.Printf("  - %d GSM secrets\n", len(keysToCreate))
		return nil
	}

	// Create GSM secrets
	gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		return fmt.Errorf("create GSM store: %w", err)
	}
	defer gsmStore.Close()

	// Build lookup for rotation config per key
	keysByName := make(map[string]addKeyInput, len(keys))
	for _, k := range keys {
		keysByName[k.keyName] = k
	}

	var keyMetadata []core.KeyMetadata
	for _, k := range keysToCreate {
		version, err := gsmStore.CreateSecretVersion(ctx, k.gsmResource, k.value)
		if err != nil {
			return fmt.Errorf("create GSM secret %s: %w", k.keyName, err)
		}
		fmt.Printf("✓ Created GSM secret: %s (version %s)\n", k.keyName, version)

		keyMetadata = append(keyMetadata, core.KeyMetadata{
			KeyName: k.keyName,
			Source:  core.SourceConfig{Kind: "gsm"},
			GSM: &core.GSMRef{
				SecretResource: k.gsmResource,
				Version:        version,
			},
			Rotation: &core.RotationConfig{
				Mode:      keysByName[k.keyName].rotationMode,
				Generator: keysByName[k.keyName].generator,
			},
		})
	}

	// Create metadata
	metadata := &core.SecretMetadata{
		ShortName:    shortName,
		ManifestPath: manifestPath,
		SealedSecret: core.SealedSecretRef{
			Name:      shortName,
			Namespace: namespace,
			Scope:     scope,
			Type:      secretType,
		},
		Status: "active",
		Keys:   keyMetadata,
	}

	// Save metadata
	metadataYAML := serializeMetadata(metadata)
	os.MkdirAll(filepath.Dir(metadataPath), 0o755)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	fmt.Printf("✓ Created metadata: %s\n", metadataPath)

	// Create SealedSecret manifest
	manifestFullPath := filepath.Join(repoPath, manifestPath)
	os.MkdirAll(filepath.Dir(manifestFullPath), 0o755)

	// Load cert for sealing
	certPath := filepath.Join(repoPath, cfg.Cert.RepoCertPath)
	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	// Seal each key and build SealedSecret
	encryptedData := make(map[string]string)
	for _, k := range keysToCreate {
		encrypted, err := sealer.Seal(shortName, namespace, k.keyName, k.value, scope)
		if err != nil {
			return fmt.Errorf("seal key %s: %w", k.keyName, err)
		}
		encryptedData[k.keyName] = encrypted
	}

	// Build SealedSecret manifest
	sealedSecret := buildSealedSecretManifest(shortName, namespace, scope, secretType, encryptedData)
	sealed, err := sealedSecret.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize SealedSecret: %w", err)
	}

	if err := writer.Write(manifestFullPath, sealed); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	fmt.Printf("✓ Created manifest: %s\n", manifestFullPath)

	fmt.Println()
	fmt.Printf("✓ Secret %s created successfully!\n", shortName)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Commit the new files: git add %s %s\n", metadataPath, manifestPath)
	fmt.Println("  2. Apply to cluster or let GitOps sync")

	return nil
}

type addKeyInput struct {
	keyName      string
	value        []byte
	rotationMode string // "static", "generated", "external"
	generator    *core.GeneratorConfig
}

func runAddInteractive(shortName, projectID string) (namespace, manifestPath, scope, secretType string, keys []addKeyInput, err error) {
	// Default values
	namespace = "default"
	manifestPath = fmt.Sprintf("apps/%s/sealed-secret.yaml", shortName)
	scope = "strict"
	secretType = "Opaque"

	// Basic info form
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Namespace").
				Description("Kubernetes namespace for this secret").
				Value(&namespace),
			huh.NewInput().
				Title("Manifest path").
				Description("Where to save the SealedSecret YAML").
				Value(&manifestPath),
			huh.NewSelect[string]().
				Title("Sealing scope").
				Options(
					huh.NewOption("strict (name+namespace bound)", "strict"),
					huh.NewOption("namespace-wide (same namespace)", "namespace-wide"),
					huh.NewOption("cluster-wide (any namespace)", "cluster-wide"),
				).
				Value(&scope),
			huh.NewSelect[string]().
				Title("Secret type").
				Options(
					huh.NewOption("Opaque", "Opaque"),
					huh.NewOption("kubernetes.io/tls", "kubernetes.io/tls"),
					huh.NewOption("kubernetes.io/dockerconfigjson", "kubernetes.io/dockerconfigjson"),
				).
				Value(&secretType),
		),
	).Run()
	if err != nil {
		return
	}

	// Add keys loop
	fmt.Println()
	fmt.Println("Add keys to this secret (press Enter with empty name to finish):")
	for {
		var keyName string
		err = huh.NewInput().
			Title("Key name").
			Description("Leave empty to finish adding keys").
			Value(&keyName).
			Run()
		if err != nil {
			return
		}

		if keyName == "" {
			break
		}

		// Value source
		var valueSource string
		err = huh.NewSelect[string]().
			Title(fmt.Sprintf("Value for '%s'", keyName)).
			Options(
				huh.NewOption("Generate random (32 bytes base64)", "random"),
				huh.NewOption("Enter value now", "enter"),
				huh.NewOption("Skip (set later)", "skip"),
			).
			Value(&valueSource).
			Run()
		if err != nil {
			return
		}

		var value []byte
		var rotationMode string
		var generator *core.GeneratorConfig
		switch valueSource {
		case "random":
			value, err = generateRandomBytes(32)
			if err != nil {
				return namespace, manifestPath, scope, secretType, nil, fmt.Errorf("generate random value: %w", err)
			}
			rotationMode = "generated"
			generator = &core.GeneratorConfig{Kind: "randomBase64", Bytes: 32}
			fmt.Printf("  Generated random value for %s\n", keyName)
		case "enter":
			var valueStr string
			err = huh.NewInput().
				Title("Enter value").
				EchoMode(huh.EchoModePassword).
				Value(&valueStr).
				Run()
			if err != nil {
				return
			}
			value = []byte(valueStr)

			// Prompt for rotation mode when user enters a value
			err = huh.NewSelect[string]().
				Title(fmt.Sprintf("Rotation mode for '%s'", keyName)).
				Description("How should this key be rotated?").
				Options(
					huh.NewOption("Static - not expected to rotate (waxseal rotate ignores)", "static"),
					huh.NewOption("External - managed externally (waxseal rotate prompts with hints)", "external"),
				).
				Value(&rotationMode).
				Run()
			if err != nil {
				return
			}
		case "skip":
			// This shouldn't happen - we need values to create GSM secrets
			return namespace, manifestPath, scope, secretType, nil, fmt.Errorf("all keys need values during creation")
		}

		keys = append(keys, addKeyInput{
			keyName:      keyName,
			value:        value,
			rotationMode: rotationMode,
			generator:    generator,
		})
	}

	if len(keys) == 0 {
		err = fmt.Errorf("at least one key is required")
		return
	}

	return
}

func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	// Return as base64 encoded
	encoded := base64.StdEncoding.EncodeToString(bytes)
	return []byte(encoded), nil
}

// buildSealedSecretManifest creates a SealedSecret structure.
func buildSealedSecretManifest(name, namespace, scope, secretType string, encryptedData map[string]string) *seal.SealedSecret {
	ss := &seal.SealedSecret{
		APIVersion: "bitnami.com/v1alpha1",
		Kind:       "SealedSecret",
		Metadata: seal.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: seal.SealedSecretSpec{
			EncryptedData: encryptedData,
		},
	}

	// Add scope annotation if not strict (strict is default)
	if scope != "strict" && scope != "" {
		if ss.Metadata.Annotations == nil {
			ss.Metadata.Annotations = make(map[string]string)
		}
		ss.Metadata.Annotations[seal.AnnotationScope] = scope
	}

	// Add template with type if not Opaque
	if secretType != "" && secretType != "Opaque" {
		ss.Spec.Template = &seal.SecretTemplateSpec{
			Type: secretType,
		}
	}

	return ss
}
