package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "addkey <shortName>",
	Short: "Add a key to a secret (or create a new secret)",
	Long: `Create a new secret with metadata, GSM entries, and SealedSecret manifest.

This command:
  1. Creates metadata in .waxseal/metadata/
  2. Creates GSM secrets for each key
  3. Generates a SealedSecret manifest

When --key flags are provided, the command uses flag values for everything
except static key values, which are prompted for securely (never in shell
history). Without --key flags, an interactive TUI wizard collects all input.

Key formats:
  --key=name                         Static key (prompts for value securely)
  --key=name:random                  Generated random value (mode: generated)
  --key=name:template=GK{{secret}}   Templated key with prefix (rotatable)

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
    --random-length=64

  # Garage S3 credentials with prefixed access key
  waxseal add garage-creds \
    --namespace=default \
    --key=access-key:template=GK{{secret}} \
    --key=secret-key:random \
    --generator=randomHex \
    --random-length=12 \
    --manifest-path=apps/infrastructure/garage/creds-sealed.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runAdd,
}

var (
	addNamespace     string
	addKeys          []string
	addManifestPath  string
	addScope         string
	addSecretType    string
	addRandomLength  int
	addGeneratorKind string
)

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVar(&addNamespace, "namespace", "", "Kubernetes namespace")
	addCmd.Flags().StringSliceVar(&addKeys, "key", nil, "Key name (use name:random or name:template=...)")
	addCmd.Flags().StringVar(&addManifestPath, "manifest-path", "", "Path for SealedSecret manifest")
	addCmd.Flags().StringVar(&addScope, "scope", "strict", "Sealing scope (strict, namespace-wide, cluster-wide)")
	addCmd.Flags().StringVar(&addSecretType, "type", "Opaque", "Secret type (Opaque, kubernetes.io/tls, etc.)")
	addCmd.Flags().StringVar(&addGeneratorKind, "generator", "randomBase64", "Generator kind (randomBase64, randomHex)")
	addCmd.Flags().IntVar(&addRandomLength, "random-length", 32, "Length of generated random values (bytes)")
	addPreflightChecks(addCmd, authNeeds{gsm: true, kubeseal: true})
}

func runAdd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shortName := args[0]

	// Check if already exists
	if files.MetadataExists(repoPath, shortName) {
		return fmt.Errorf("secret %q already exists", shortName)
	}
	metadataPath := files.MetadataPath(repoPath, shortName)

	// Load config for project ID
	cfg, err := resolveConfig()
	if err != nil {
		return fmt.Errorf("run 'waxseal setup' first: %w", err)
	}

	// Collect input (interactive or flags)
	var namespace, manifestPath, scope, secretType string
	var keys []addKeyInput

	if len(addKeys) > 0 {
		// Non-interactive: --key flags provide all input
		if addNamespace == "" {
			return fmt.Errorf("--namespace is required when using --key flags")
		}

		// Validate generator kind early
		if err := ValidateGeneratorKind(addGeneratorKind); err != nil {
			return err
		}

		namespace = addNamespace
		scope = addScope
		secretType = addSecretType
		manifestPath = addManifestPath
		if manifestPath == "" {
			manifestPath = fmt.Sprintf("apps/%s/sealed-secret.yaml", shortName)
		}

		// Parse keys using shared helper
		for _, k := range addKeys {
			spec, err := ParseKeySpec(k)
			if err != nil {
				return fmt.Errorf("invalid key spec %q: %w", k, err)
			}

			var value []byte
			var generator *core.GeneratorConfig
			var templateStr string

			switch spec.Kind {
			case "random":
				// Generated key with configured generator
				generator = &core.GeneratorConfig{Kind: addGeneratorKind, Bytes: addRandomLength}
				value, err = core.GenerateValue(generator)
				if err != nil {
					return fmt.Errorf("generate value for key %q: %w", spec.Name, err)
				}

			case "template":
				// Templated key - generate secret, create JSON payload
				// Auto-detect generator kind from well-known prefix patterns
				genKind := addGeneratorKind
				genBytes := addRandomLength
				for _, p := range template.WellKnownPrefixes() {
					if strings.HasPrefix(spec.Template, p.Prefix+"{{") {
						if genKind != p.SecretKind {
							fmt.Printf("  Auto-selecting generator %s for %s prefix (%s)\n", p.SecretKind, p.Prefix, p.Description)
							genKind = p.SecretKind
						}
						if genBytes == 32 { // default not overridden
							genBytes = p.SecretBytes
						}
						break
					}
				}
				generator = &core.GeneratorConfig{Kind: genKind, Bytes: genBytes}
				secretValue, err := core.GenerateValue(generator)
				if err != nil {
					return fmt.Errorf("generate secret for key %q: %w", spec.Name, err)
				}
				// Convert core.GeneratorConfig to template.GeneratorConfig for payload
				templateGen := &template.GeneratorConfig{Kind: generator.Kind, Bytes: generator.Bytes}
				// Create template payload - value will be the JSON, not the computed value
				payload, err := template.NewPayload(spec.Template, map[string]string{}, string(secretValue), templateGen)
				if err != nil {
					return fmt.Errorf("create template payload for key %q: %w", spec.Name, err)
				}
				templateStr = spec.Template
				// For templated keys, the GSM value is the JSON payload
				value, err = payload.Marshal()
				if err != nil {
					return fmt.Errorf("marshal template payload for key %q: %w", spec.Name, err)
				}

			case "static":
				// Static key - prompt for value securely
				inputValue, err := PromptSecretValue(spec.Name)
				if err != nil {
					return fmt.Errorf("prompt for key %q: %w", spec.Name, err)
				}
				value = []byte(inputValue)
			}

			keys = append(keys, addKeyInput{
				keyName:      spec.Name,
				value:        value,
				rotationMode: spec.RotationMode,
				generator:    generator,
				isTemplated:  spec.Kind == "template",
				template:     templateStr,
			})
		}
	} else {
		// Interactive mode
		var err error
		namespace, manifestPath, scope, secretType, keys, err = runAddInteractive(shortName)
		if err != nil {
			return err
		}
	}

	// Generate GSM resource paths
	type keyToCreate struct {
		keyName     string
		value       []byte // For templated keys, this is the JSON payload
		sealValue   []byte // The value to seal (computed value for templated keys)
		gsmResource string
		isTemplated bool
		template    string
	}
	var keysToCreate []keyToCreate
	for _, k := range keys {
		gsmResource := store.SecretResource(cfg.Store.ProjectID, store.FormatSecretID(shortName, k.keyName))

		// For templated keys, we need to extract the computed value for sealing
		var sealValue []byte
		if k.isTemplated {
			// Parse the JSON payload to get the computed value
			payload, err := template.ParsePayload(k.value)
			if err != nil {
				return fmt.Errorf("parse template payload for %s: %w", k.keyName, err)
			}
			sealValue = []byte(payload.Computed)
		} else {
			sealValue = k.value
		}

		keysToCreate = append(keysToCreate, keyToCreate{
			keyName:     k.keyName,
			value:       k.value,
			sealValue:   sealValue,
			gsmResource: gsmResource,
			isTemplated: k.isTemplated,
			template:    k.template,
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
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

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
		printSuccess("Created GSM secret: %s (version %s)", k.keyName, version)

		input := keysByName[k.keyName]

		if k.isTemplated {
			// Templated key: use computed source with GSM-backed payload
			keyMetadata = append(keyMetadata, core.KeyMetadata{
				KeyName: k.keyName,
				Source:  core.SourceConfig{Kind: "computed"},
				Computed: &core.ComputedConfig{
					Kind:     "template",
					Template: k.template,
					GSM: &core.GSMRef{
						SecretResource: k.gsmResource,
						Version:        version,
					},
				},
				Rotation: &core.RotationConfig{
					Mode:      input.rotationMode,
					Generator: input.generator,
				},
			})
		} else {
			// Regular key: use GSM source
			keyMetadata = append(keyMetadata, core.KeyMetadata{
				KeyName: k.keyName,
				Source:  core.SourceConfig{Kind: "gsm"},
				GSM: &core.GSMRef{
					SecretResource: k.gsmResource,
					Version:        version,
				},
				Rotation: &core.RotationConfig{
					Mode:      input.rotationMode,
					Generator: input.generator,
				},
			})
		}
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
	metadataYAML := files.SerializeMetadata(metadata)
	os.MkdirAll(filepath.Dir(metadataPath), 0o755)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	printSuccess("Created metadata: %s", metadataPath)

	// Create SealedSecret manifest
	manifestFullPath := filepath.Join(repoPath, manifestPath)
	os.MkdirAll(filepath.Dir(manifestFullPath), 0o755)

	// Use kubeseal binary for encryption (guarantees controller compatibility)
	sealer := resolveSealer(cfg)

	// Seal each key and build SealedSecret
	encryptedData := make(map[string]string)
	for _, k := range keysToCreate {
		// For templated keys, seal the computed value (not the JSON payload)
		encrypted, err := sealer.Seal(shortName, namespace, k.keyName, k.sealValue, scope)
		if err != nil {
			return fmt.Errorf("seal key %s: %w", k.keyName, err)
		}
		encryptedData[k.keyName] = encrypted
	}

	// Build SealedSecret manifest
	sealedSecret := seal.NewSealedSecret(shortName, namespace, scope, secretType, encryptedData)
	sealed, err := sealedSecret.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize SealedSecret: %w", err)
	}

	if err := writer.Write(manifestFullPath, sealed); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	printSuccess("Created manifest: %s", manifestFullPath)

	fmt.Println()
	printSuccess("Secret %s created successfully!", shortName)
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
	isTemplated  bool   // True if this is a templated key with JSON payload
	template     string // Template string (only if isTemplated)
}

func runAddInteractive(shortName string) (namespace, manifestPath, scope, secretType string, keys []addKeyInput, err error) {
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
			generator = &core.GeneratorConfig{Kind: "randomBase64", Bytes: 32}
			value, err = core.GenerateValue(generator)
			if err != nil {
				return namespace, manifestPath, scope, secretType, nil, fmt.Errorf("generate random value: %w", err)
			}
			rotationMode = "generated"
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
