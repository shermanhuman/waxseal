package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "updatekey <shortName> <keyName>",
	Short: "Update an existing key's value",
	Long: `Update a secret key's value in GSM and reseal the SealedSecret.

This command:
  1. Creates a new version in GSM with the new value
  2. Updates the metadata with the new version number
  3. Reseals the SealedSecret manifest

For computed (templated) keys, this command allows updating template
parameters (host, port, username) or the template string itself.
Use 'waxseal rotate' to update the secret portion.

Examples:
  # Interactive mode (prompts for new value)
  waxseal updatekey my-app-secrets api_key

  # Generate new random value
  waxseal updatekey my-app-secrets api_key --generate-random

  # From stdin
  echo "new-value" | waxseal updatekey my-app-secrets api_key --stdin

  # Preview changes
  waxseal updatekey my-app-secrets api_key --generate-random --dry-run`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdate,
}

var (
	updateFromStdin      bool
	updateGenerateRandom bool
	updateRandomLength   int
	updateCreateKey      bool
)

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&updateFromStdin, "stdin", false, "Read new value from stdin")
	updateCmd.Flags().BoolVar(&updateGenerateRandom, "generate-random", false, "Generate a random value")
	updateCmd.Flags().IntVar(&updateRandomLength, "random-length", 32, "Length of generated random value (bytes)")
	updateCmd.Flags().BoolVar(&updateCreateKey, "create", false, "Create the key if it doesn't exist")
	addPreflightChecks(updateCmd, authNeeds{gsm: true, kubeseal: true})
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shortName := args[0]
	keyName := args[1]

	// Load config first (needed for GSM resource generation)
	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	// Load metadata
	metadata, err := files.LoadMetadata(repoPath, shortName)
	if err != nil {
		return err
	}
	metadataPath := files.MetadataPath(repoPath, shortName)

	if metadata.IsRetired() {
		return fmt.Errorf("cannot update retired secret %q", shortName)
	}

	// Find the key (or prepare to create it)
	var keyIndex = -1
	for i, k := range metadata.Keys {
		if k.KeyName == keyName {
			keyIndex = i
			break
		}
	}

	// If key not found, require --create flag or prompt
	createNewKey := false
	var newKeyRotationMode string = "external"
	var newKeyGenType string
	if keyIndex == -1 {
		if !updateCreateKey {
			// Interactive prompt
			var shouldCreate bool
			err := huh.NewConfirm().
				Title(fmt.Sprintf("Key '%s' not found in secret '%s'", keyName, shortName)).
				Description("Do you want to create it?").
				Value(&shouldCreate).
				Run()
			if err != nil {
				return err
			}
			if !shouldCreate {
				return fmt.Errorf("key %q not found in secret %q", keyName, shortName)
			}
		}
		createNewKey = true

		// Collect key configuration (same prompts as discover wizard)
		err = huh.NewSelect[string]().
			Title("Rotation mode").
			Description("How should this key be rotated?").
			Options(
				huh.NewOption("Static - not expected to rotate (waxseal rotate ignores)", "static"),
				huh.NewOption("Generated - waxseal auto-rotates", "generated"),
				huh.NewOption("External - managed externally (waxseal rotate prompts with hints)", "external"),
			).
			Value(&newKeyRotationMode).
			Run()
		if err != nil {
			return err
		}

		// If generated, ask for generator type
		if newKeyRotationMode == "generated" {
			err = huh.NewSelect[string]().
				Title("Generator type").
				Description("How should the secret value be generated?").
				Options(
					huh.NewOption("Random Base64 (URL-safe, good for tokens/passwords)", "randomBase64"),
					huh.NewOption("Random Hex (hexadecimal string)", "randomHex"),
				).
				Value(&newKeyGenType).
				Run()
			if err != nil {
				return err
			}
		}
	}

	var keyMeta *core.KeyMetadata
	var gsmResource string

	if !createNewKey {
		keyMeta = &metadata.Keys[keyIndex]

		// Computed keys require special handling - delegate to the computed key update flow
		if keyMeta.Source.Kind == "computed" {
			return updateComputedKey(ctx, cfg, metadata, keyMeta, metadataPath)
		}

		if keyMeta.GSM == nil {
			return fmt.Errorf("key %q has no GSM reference", keyName)
		}
		gsmResource = keyMeta.GSM.SecretResource

		// If rotation mode is unknown or missing, prompt to configure it
		if keyMeta.Rotation == nil || keyMeta.Rotation.Mode == "" || keyMeta.Rotation.Mode == "unknown" {
			fmt.Printf("  Key '%s' has no rotation mode configured.\n", keyName)
			err = huh.NewSelect[string]().
				Title("Rotation mode").
				Description("How should this key be rotated?").
				Options(
					huh.NewOption("Static - not expected to rotate (waxseal rotate ignores)", "static"),
					huh.NewOption("Generated - waxseal auto-rotates", "generated"),
					huh.NewOption("External - managed externally (waxseal rotate prompts with hints)", "external"),
				).
				Value(&newKeyRotationMode).
				Run()
			if err != nil {
				return err
			}

			// Update the rotation config
			if keyMeta.Rotation == nil {
				keyMeta.Rotation = &core.RotationConfig{}
			}
			keyMeta.Rotation.Mode = newKeyRotationMode

			// If generated, ask for generator type
			if newKeyRotationMode == "generated" {
				err = huh.NewSelect[string]().
					Title("Generator type").
					Description("How should the secret value be generated?").
					Options(
						huh.NewOption("Random Base64 (URL-safe, good for tokens/passwords)", "randomBase64"),
						huh.NewOption("Random Hex (hexadecimal string)", "randomHex"),
					).
					Value(&newKeyGenType).
					Run()
				if err != nil {
					return err
				}
				keyMeta.Rotation.Generator = &core.GeneratorConfig{
					Kind:  newKeyGenType,
					Bytes: 32,
				}
			}
		}
	} else {
		// Generate GSM resource for new key
		gsmResource = store.SecretResource(cfg.Store.ProjectID, store.FormatSecretID(shortName, keyName))
	}

	// Get new value
	var newValue []byte
	if updateGenerateRandom {
		var err error
		newValue, err = core.GenerateValue(&core.GeneratorConfig{Kind: "randomBase64", Bytes: updateRandomLength})
		if err != nil {
			return fmt.Errorf("generate random bytes: %w", err)
		}
		fmt.Printf("Generated random value (%d bytes, base64 encoded)\n", updateRandomLength)
	} else if updateFromStdin {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read from stdin: %w", err)
		}
		newValue = []byte(strings.TrimRight(line, "\n\r"))
	} else {
		// Interactive prompt
		var valueStr string
		err := huh.NewInput().
			Title(fmt.Sprintf("New value for %s", keyName)).
			EchoMode(huh.EchoModePassword).
			Value(&valueStr).
			Run()
		if err != nil {
			return err
		}
		newValue = []byte(valueStr)
	}

	if len(newValue) == 0 {
		return fmt.Errorf("value cannot be empty")
	}

	// Show summary
	fmt.Println()
	if createNewKey {
		fmt.Printf("Creating key: %s/%s\n", shortName, keyName)
	} else {
		fmt.Printf("Updating key: %s/%s\n", shortName, keyName)
	}
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  GSM Resource: %s\n", gsmResource)
	if !createNewKey {
		fmt.Printf("  Old Version:  %s\n", keyMeta.GSM.Version)
	}
	fmt.Println()

	if dryRun {
		fmt.Println("[DRY RUN] Would:")
		fmt.Println("  1. Create new version in GSM")
		fmt.Println("  2. Update metadata with new version")
		fmt.Println("  3. Reseal SealedSecret manifest")
		return nil
	}

	// Create new GSM version
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	newVersion, err := gsmStore.CreateSecretVersion(ctx, gsmResource, newValue)
	if err != nil {
		return fmt.Errorf("create GSM version: %w", err)
	}
	printSuccess("Created new GSM version: %s", newVersion)

	// Update or create metadata for this key
	if createNewKey {
		// Add new key to metadata
		newKeyMeta := core.KeyMetadata{
			KeyName: keyName,
			Source:  core.SourceConfig{Kind: "gsm"},
			GSM: &core.GSMRef{
				SecretResource: gsmResource,
				Version:        newVersion,
			},
			Rotation: &core.RotationConfig{Mode: newKeyRotationMode},
		}
		// Add generator config if rotation mode is generated
		if newKeyRotationMode == "generated" && newKeyGenType != "" {
			newKeyMeta.Rotation.Generator = &core.GeneratorConfig{
				Kind:  newKeyGenType,
				Bytes: 32,
			}
		}
		metadata.Keys = append(metadata.Keys, newKeyMeta)
		printSuccess("Added key %s to metadata", keyName)
	} else {
		keyMeta.GSM.Version = newVersion
		printSuccess("Updated metadata: version %s", newVersion)
	}
	metadataYAML := files.SerializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	// Reseal the SealedSecret
	manifestPath := filepath.Join(repoPath, metadata.ManifestPath)

	// Read existing manifest
	existingManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	existingSS, err := seal.ParseSealedSecret(existingManifest)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// Use kubeseal binary for encryption (guarantees controller compatibility)
	sealer := resolveSealer(cfg)

	// Seal the new value
	scope := existingSS.GetScope()
	encrypted, err := sealer.Seal(
		metadata.SealedSecret.Name,
		metadata.SealedSecret.Namespace,
		keyName,
		newValue,
		scope,
	)
	if err != nil {
		return fmt.Errorf("seal value: %w", err)
	}

	// Update the encrypted data
	existingSS.Spec.EncryptedData[keyName] = encrypted

	// Write updated manifest
	updatedYAML, err := existingSS.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}

	if err := writer.Write(manifestPath, updatedYAML); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	printSuccess("Updated manifest: %s", metadata.ManifestPath)

	fmt.Println()
	printSuccess("Key %s/%s updated successfully!", shortName, keyName)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Commit the updated files")
	fmt.Println("  2. Apply to cluster or let GitOps sync")

	return nil
}

// updateComputedKey handles updating a computed (templated) key.
// This allows editing template parameters without changing the secret value.
func updateComputedKey(ctx context.Context, cfg *config.Config, metadata *core.SecretMetadata, keyMeta *core.KeyMetadata, metadataPath string) error {
	shortName := metadata.ShortName
	keyName := keyMeta.KeyName

	// Must have computed config
	if keyMeta.Computed == nil || keyMeta.Computed.GSM == nil {
		return fmt.Errorf("key %q is marked as computed but has no GSM reference — use 'waxseal rotate' instead", keyName)
	}

	// Get GSM store
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	// Load existing payload from GSM
	gsmRef := keyMeta.Computed.GSM
	payloadBytes, err := gsmStore.AccessVersion(ctx, gsmRef.SecretResource, gsmRef.Version)
	if err != nil {
		return fmt.Errorf("load computed key payload: %w", err)
	}

	payload, err := template.ParsePayload(payloadBytes)
	if err != nil {
		return fmt.Errorf("parse computed key payload: %w", err)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("━", 64))
	fmt.Printf("%s📐 Update Computed Key: %s/%s%s\n", styleBold, shortName, keyName, styleReset)
	fmt.Println(strings.Repeat("━", 64))
	fmt.Println()
	fmt.Printf("Template: %s\n", payload.Template)
	fmt.Println()

	// Ask what to update
	var updateChoice string
	err = huh.NewSelect[string]().
		Title("What do you want to update?").
		Options(
			huh.NewOption("📝 Update template parameters (host, port, username, etc.)", "params"),
			huh.NewOption("📐 Update the template string", "template"),
			huh.NewOption("🔄 Update the secret — use 'waxseal rotate' instead", "secret"),
		).
		Value(&updateChoice).
		Run()
	if err != nil {
		return err
	}

	if updateChoice == "secret" {
		fmt.Println()
		printDim("To update the secret portion of a computed key, use:")
		fmt.Printf("  waxseal rotate %s %s\n", shortName, keyName)
		fmt.Println()
		return nil
	}

	if updateChoice == "template" {
		// Update the template string
		var newTemplate string
		err = huh.NewInput().
			Title("New template string").
			Description("Use {{secret}} for the rotatable portion, {{param}} for other values").
			Placeholder(payload.Template).
			Value(&newTemplate).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("template cannot be empty")
				}
				if !strings.Contains(s, "{{secret}}") {
					return fmt.Errorf("template must contain {{secret}} placeholder")
				}
				return nil
			}).
			Run()
		if err != nil {
			return err
		}
		payload.Template = newTemplate
	}

	if updateChoice == "params" {
		// Show current params and allow editing each
		if len(payload.Values) == 0 {
			fmt.Println("This computed key has no template parameters to update.")
			fmt.Println("Only {{secret}} is used in the template.")
			printDim("Use 'waxseal rotate %s %s' to update the secret.", shortName, keyName)
			return nil
		}

		fmt.Println("Current parameters:")
		sortedParams := make([]string, 0, len(payload.Values))
		for k := range payload.Values {
			sortedParams = append(sortedParams, k)
		}
		sort.Strings(sortedParams)
		for _, k := range sortedParams {
			fmt.Printf("  %s: %s\n", k, payload.Values[k])
		}
		fmt.Println()

		// Ask which param to update
		var paramOptions []huh.Option[string]
		for _, k := range sortedParams {
			paramOptions = append(paramOptions, huh.NewOption(fmt.Sprintf("%s = %s", k, payload.Values[k]), k))
		}
		paramOptions = append(paramOptions, huh.NewOption("(done updating)", ""))

		for {
			var paramToUpdate string
			err = huh.NewSelect[string]().
				Title("Select a parameter to update").
				Options(paramOptions...).
				Value(&paramToUpdate).
				Run()
			if err != nil {
				return err
			}

			if paramToUpdate == "" {
				break // done
			}

			var newValue string
			err = huh.NewInput().
				Title(fmt.Sprintf("New value for '%s'", paramToUpdate)).
				Placeholder(payload.Values[paramToUpdate]).
				Value(&newValue).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("value cannot be empty")
					}
					return nil
				}).
				Run()
			if err != nil {
				return err
			}
			payload.Values[paramToUpdate] = newValue

			// Rebuild options with updated values
			paramOptions = []huh.Option[string]{}
			for _, k := range sortedParams {
				paramOptions = append(paramOptions, huh.NewOption(fmt.Sprintf("%s = %s", k, payload.Values[k]), k))
			}
			paramOptions = append(paramOptions, huh.NewOption("(done updating)", ""))
		}
	}

	// Recompute the value
	newPayload, err := template.NewPayload(payload.Template, payload.Values, payload.Secret, payload.Generator)
	if err != nil {
		return fmt.Errorf("recompute payload: %w", err)
	}

	fmt.Println()
	fmt.Println("Updated computed value:")
	printDim("  (preview) %s", newPayload.Computed)
	fmt.Println()

	if dryRun {
		printDim("[DRY RUN] Would update computed key — no changes made")
		return nil
	}

	proceed, err := confirm("Save these changes?")
	if err != nil || !proceed {
		return fmt.Errorf("cancelled")
	}

	// Marshal and store new payload
	payloadJSON, err := newPayload.Marshal()
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	newVersion, err := gsmStore.CreateSecretVersion(ctx, gsmRef.SecretResource, payloadJSON)
	if err != nil {
		return fmt.Errorf("create GSM version: %w", err)
	}
	printSuccess("Created new GSM version: %s", newVersion)

	// Update metadata
	keyMeta.Computed.GSM.Version = newVersion
	if updateChoice == "template" {
		keyMeta.Computed.Template = newPayload.Template
	}

	metadataYAML := files.SerializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	printSuccess("Updated metadata")

	// Reseal the SealedSecret
	manifestPath := filepath.Join(repoPath, metadata.ManifestPath)
	existingManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	existingSS, err := seal.ParseSealedSecret(existingManifest)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	sealer := resolveSealer(cfg)
	scope := existingSS.GetScope()
	encrypted, err := sealer.Seal(
		metadata.SealedSecret.Name,
		metadata.SealedSecret.Namespace,
		keyName,
		[]byte(newPayload.Computed),
		scope,
	)
	if err != nil {
		return fmt.Errorf("seal value: %w", err)
	}

	existingSS.Spec.EncryptedData[keyName] = encrypted
	updatedYAML, err := existingSS.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}

	if err := writer.Write(manifestPath, updatedYAML); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	printSuccess("Updated manifest: %s", metadata.ManifestPath)

	fmt.Println()
	printSuccess("Computed key %s/%s updated!", shortName, keyName)
	fmt.Println()

	return nil
}
