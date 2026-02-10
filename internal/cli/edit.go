package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/logging"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
	"github.com/spf13/cobra"
)

// Special value returned when user selects "Create a new Secret"
const createNewSecretMarker = "__CREATE_NEW_SECRET__"

var editCmd = &cobra.Command{
	Use:   "edit [shortName]",
	Short: "Interactively create, update, or retire Secrets",
	Long: `Interactive wizard for managing SealedSecrets.

Without arguments, presents a Secret picker then an action menu.
With a shortName, jumps directly to the action menu for that Secret.

Actions:
  Create     - Create a new Secret with keys
  Add key    - Add a new key to the Secret
  Update key - Update an existing key's value
  Retire     - Mark the Secret as retired

Examples:
  # Interactive: pick Secret or create new, then pick action
  waxseal edit

  # Interactive: pick action for a specific Secret
  waxseal edit my-app-secrets

  # Jump straight to a specific action
  waxseal edit addkey
  waxseal edit updatekey
  waxseal edit retirekey`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEdit,
}

// Subcommands for direct action access
var editAddkeyCmd = &cobra.Command{
	Use:   "addkey",
	Short: "Interactive add-key wizard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditWithAction(cmd.Context(), "addkey")
	},
}

var editUpdatekeyCmd = &cobra.Command{
	Use:   "updatekey",
	Short: "Interactive update-key wizard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditWithAction(cmd.Context(), "updatekey")
	},
}

var editRetirekeyCmd = &cobra.Command{
	Use:   "retirekey",
	Short: "Interactive retire-key wizard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditWithAction(cmd.Context(), "retirekey")
	},
}

func init() {
	rootCmd.AddCommand(editCmd)
	editCmd.AddCommand(editAddkeyCmd)
	editCmd.AddCommand(editUpdatekeyCmd)
	editCmd.AddCommand(editRetirekeyCmd)

	// Note: We don't require metadata for edit command anymore since we allow creating new Secrets
	addMetadataCheck(editAddkeyCmd)
	addMetadataCheck(editUpdatekeyCmd)
	addMetadataCheck(editRetirekeyCmd)
	addPreflightChecks(editCmd, authNeeds{gsm: true, kubeseal: true})
	addPreflightChecks(editAddkeyCmd, authNeeds{gsm: true})
	addPreflightChecks(editUpdatekeyCmd, authNeeds{gsm: true})
	addPreflightChecks(editRetirekeyCmd, authNeeds{gsm: true})
}

// ── Shared helpers ─────────────────────────────────────────────────────────

// pickSecret presents a TUI Secret picker and returns the selected metadata.
// If allowCreate is true, adds "Create a new Secret" as the first option.
// Returns nil, nil with shortName == createNewSecretMarker if user chooses to create.
func pickSecret(title string, filter func(*core.SecretMetadata) bool, allowCreate bool) (*core.SecretMetadata, string, error) {
	allSecrets, loadErrs := files.LoadAllMetadataCollectErrors(repoPath)
	for _, err := range loadErrs {
		logging.Warn("skipping malformed metadata", "error", err)
	}

	// Build options: "Create new" first (if allowed), then active, then retired
	var options []huh.Option[string]
	lookup := make(map[string]*core.SecretMetadata)

	if allowCreate {
		options = append(options, huh.NewOption("✨ Create a new Secret", createNewSecretMarker))
	}

	var activeOpts, retiredOpts []huh.Option[string]
	for _, s := range allSecrets {
		if filter != nil && !filter(s) {
			continue
		}
		lookup[s.ShortName] = s
		label := fmt.Sprintf("%s (%d keys)", s.ShortName, len(s.Keys))
		if s.IsRetired() {
			label = s.ShortName + " (retired)"
			retiredOpts = append(retiredOpts, huh.NewOption(label, s.ShortName))
		} else {
			activeOpts = append(activeOpts, huh.NewOption(label, s.ShortName))
		}
	}

	options = append(options, activeOpts...)
	options = append(options, retiredOpts...)

	if len(options) == 0 {
		return nil, "", nil
	}

	var shortName string
	err := huh.NewSelect[string]().
		Title(title).
		Options(options...).
		Value(&shortName).
		Run()
	if err != nil {
		return nil, "", fmt.Errorf("selection cancelled: %w", err)
	}

	if shortName == createNewSecretMarker {
		return nil, createNewSecretMarker, nil
	}

	return lookup[shortName], shortName, nil
}

// pickAction presents the action menu for a loaded Secret.
func pickAction(metadata *core.SecretMetadata) (string, error) {
	// Show context with nice formatting
	fmt.Println()
	fmt.Printf("  %sSecret:%s  %s\n", styleBold, styleReset, metadata.ShortName)
	fmt.Printf("  %sStatus:%s  %s\n", styleBold, styleReset, statusLabel(metadata.Status))
	fmt.Printf("  %sKeys:%s    %s\n", styleBold, styleReset, keysSummary(metadata.Keys))
	fmt.Println()

	var actions []huh.Option[string]
	if metadata.IsRetired() {
		actions = []huh.Option[string]{
			huh.NewOption("📄 View metadata", "view"),
		}
	} else {
		actions = []huh.Option[string]{
			huh.NewOption("➕ Add a new key", "addkey"),
			huh.NewOption("✏️  Update an existing key", "updatekey"),
			huh.NewOption("🗑️  Retire this Secret", "retirekey"),
			huh.NewOption("📄 View metadata", "view"),
		}
	}

	var action string
	err := huh.NewSelect[string]().
		Title("What would you like to do?").
		Options(actions...).
		Value(&action).
		Run()
	if err != nil {
		return "", fmt.Errorf("selection cancelled: %w", err)
	}
	return action, nil
}

// dispatch calls the underlying command for the chosen action.
// Note: preflight checks (GSM auth, metadata) are on editCmd itself,
// so they fire before dispatch is reached.
func dispatch(ctx context.Context, action string, metadata *core.SecretMetadata) error {
	switch action {
	case "addkey":
		return addKeyToExistingSecret(ctx, metadata.ShortName)

	case "updatekey":
		if len(metadata.Keys) == 0 {
			return fmt.Errorf("Secret %q has no keys", metadata.ShortName)
		}
		var keyOptions []huh.Option[string]
		for _, k := range metadata.Keys {
			label := k.KeyName
			if k.Rotation != nil {
				label += fmt.Sprintf(" (mode: %s)", k.Rotation.Mode)
			}
			keyOptions = append(keyOptions, huh.NewOption(label, k.KeyName))
		}
		var keyName string
		err := huh.NewSelect[string]().
			Title("Select a key to update").
			Options(keyOptions...).
			Value(&keyName).
			Run()
		if err != nil {
			return fmt.Errorf("selection cancelled: %w", err)
		}
		return updateCmd.RunE(updateCmd, []string{metadata.ShortName, keyName})

	case "retirekey":
		return retireCmd.RunE(retireCmd, []string{metadata.ShortName})

	case "view":
		return metaShowKeyCmd.RunE(metaShowKeyCmd, []string{metadata.ShortName})

	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

// ── Commands ───────────────────────────────────────────────────────────────

func runEdit(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	var metadata *core.SecretMetadata
	var err error

	if len(args) == 1 {
		// Load the named Secret directly
		metadata, err = files.LoadMetadata(repoPath, args[0])
		if err != nil {
			return fmt.Errorf("Secret %q not found: %w", args[0], err)
		}
	} else {
		var shortName string
		metadata, shortName, err = pickSecret("Select a Secret to edit", nil, true)
		if err != nil {
			return err
		}

		// User chose to create a new Secret
		if shortName == createNewSecretMarker {
			return runCreateSecretWizard(ctx)
		}

		if metadata == nil {
			fmt.Println("No Secrets registered. Creating a new one...")
			return runCreateSecretWizard(ctx)
		}
	}

	action, err := pickAction(metadata)
	if err != nil {
		return err
	}
	return dispatch(ctx, action, metadata)
}

// runEditWithAction is used by edit subcommands — picks a Secret, then runs the action.
func runEditWithAction(ctx context.Context, action string) error {
	filter := func(s *core.SecretMetadata) bool {
		if action == "retirekey" {
			return !s.IsRetired()
		}
		return true
	}

	metadata, shortName, err := pickSecret(fmt.Sprintf("Select a Secret to %s", action), filter, false)
	if err != nil {
		return err
	}
	if metadata == nil && shortName != createNewSecretMarker {
		if action == "addkey" {
			// No secrets exist — offer to create one via the full wizard
			fmt.Println("No Secrets registered. Creating a new one...")
			return runCreateSecretWizard(ctx)
		}
		return fmt.Errorf("no eligible Secrets for %s", action)
	}

	return dispatch(ctx, action, metadata)
}

// statusLabel returns a human-readable status label.
func statusLabel(status string) string {
	switch status {
	case "retired":
		return "🔴 retired"
	case "active", "":
		return "🟢 active"
	default:
		return status
	}
}

// keysSummary returns a compact summary of keys.
func keysSummary(keys []core.KeyMetadata) string {
	if len(keys) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.KeyName)
	}
	summary := strings.Join(names, ", ")
	if len(summary) > 60 {
		return fmt.Sprintf("%d keys", len(keys))
	}
	return summary
}

// ── Shared Key Input Types ─────────────────────────────────────────────────

// keyInputData holds the data collected from the add-key wizard.
// Used by both create-secret and add-key-to-existing flows.
type keyInputData struct {
	keyName      string
	value        []byte
	rotationMode string
	generator    *core.GeneratorConfig
	// Computed key fields
	isComputed    bool
	tmplString    string            // Template string (e.g., "postgresql://{{username}}:{{secret}}@{{host}}/{{database}}")
	tmplValues    map[string]string // Static values for the template
	tmplSecret    string            // The secret value for {{secret}}
	tmplGenerator *template.GeneratorConfig
}

// collectSingleKeyInput prompts the user for a single key's data.
// Returns the keyInputData and a bool indicating if data was collected (false if user wants to stop).
func collectSingleKeyInput(keyName string, existingKeys []string) (*keyInputData, error) {
	// Check for duplicate
	for _, existing := range existingKeys {
		if existing == keyName {
			printWarning("Key %q already exists, skipping", keyName)
			return nil, nil
		}
	}

	// Value source
	var valueSource string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Value for '%s'", keyName)).
		Options(
			huh.NewOption("🎲 Generate random (32 bytes, base64)", "random"),
			huh.NewOption("✏️  Enter value now (masked)", "enter"),
			huh.NewOption("📐 Computed (templated connection string)", "computed"),
		).
		Value(&valueSource).
		Run()
	if err != nil {
		return nil, err
	}

	var value []byte
	var rotationMode string
	var generator *core.GeneratorConfig

	switch valueSource {
	case "random":
		genKind, genErr := PromptGeneratorKind(keyName)
		if genErr != nil {
			return nil, genErr
		}
		generator = &core.GeneratorConfig{Kind: genKind, Bytes: 32}
		value, err = core.GenerateValue(generator)
		if err != nil {
			return nil, fmt.Errorf("generate random value: %w", err)
		}
		rotationMode = "generated"
		printSuccess("Generated random %s value for %s", genKind, keyName)

	case "enter":
		var valueStr string
		err = huh.NewInput().
			Title("Enter value").
			EchoMode(huh.EchoModePassword).
			Value(&valueStr).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("value cannot be empty")
				}
				return nil
			}).
			Run()
		if err != nil {
			return nil, err
		}
		value = []byte(valueStr)

		// Rotation mode for manual values
		err = huh.NewSelect[string]().
			Title(fmt.Sprintf("Rotation mode for '%s'", keyName)).
			Description("How should this key be rotated in the future?").
			Options(
				huh.NewOption("Static — rarely changes, rotate manually", "static"),
				huh.NewOption("External — managed externally (shows hints during rotate)", "external"),
			).
			Value(&rotationMode).
			Run()
		if err != nil {
			return nil, err
		}
	}

	// Computed key fields (only set when valueSource == "computed")
	var isComputed bool
	var tmplString string
	var tmplValues map[string]string
	var tmplSecret string
	var tmplGenerator *template.GeneratorConfig

	if valueSource == "computed" {
		isComputed = true

		// Prompt for full connection string
		var connString string
		err = huh.NewInput().
			Title("Enter the full connection string").
			Description("Password/secret portion will become {{secret}}").
			Placeholder("postgresql://user:password@host:5432/database").
			Value(&connString).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("connection string is required")
				}
				if !strings.Contains(s, "://") {
					return fmt.Errorf("must be a URL-style connection string (e.g., postgresql://...)")
				}
				return nil
			}).
			Run()
		if err != nil {
			return nil, err
		}

		// Auto-detect template and extract values
		isTemplate, detected, extractedValues := template.DetectConnectionString(connString, nil)
		if !isTemplate {
			printWarning("Could not auto-detect connection string format.")
			printDim("Enter a template manually using {{secret}} for the rotatable part.")
			fmt.Println()
			var manualTemplate string
			err = huh.NewInput().
				Title("Template string").
				Description("Use {{secret}} for the password/secret portion").
				Placeholder(connString).
				Value(&manualTemplate).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("template is required")
					}
					if !strings.Contains(s, "{{secret}}") {
						return fmt.Errorf("template must contain {{secret}} placeholder")
					}
					return nil
				}).
				Run()
			if err != nil {
				return nil, err
			}
			tmplString = manualTemplate
			tmplValues = make(map[string]string)
			tmplSecret = ""
		} else {
			tmplString = detected
			tmplValues = extractedValues
			fmt.Println()
			printSuccess("Detected template:")
			fmt.Printf("  %s\n", tmplString)
			fmt.Println()
			printDim("Extracted values:")
			sortedKeys := make([]string, 0, len(tmplValues))
			for k := range tmplValues {
				sortedKeys = append(sortedKeys, k)
			}
			sort.Strings(sortedKeys)
			for _, k := range sortedKeys {
				fmt.Printf("  %s: %s\n", k, tmplValues[k])
			}
			fmt.Println()
		}

		// Secret handling
		var secretSource string
		err = huh.NewSelect[string]().
			Title("How should the secret be managed?").
			Description("The {{secret}} placeholder in the template").
			Options(
				huh.NewOption("🎲 Generate new random secret", "generate"),
				huh.NewOption("✏️  Keep entered password as secret", "keep"),
				huh.NewOption("✏️  Enter a different secret value", "enter"),
			).
			Value(&secretSource).
			Run()
		if err != nil {
			return nil, err
		}

		switch secretSource {
		case "generate":
			genKind, genErr := PromptGeneratorKind(keyName)
			if genErr != nil {
				return nil, genErr
			}
			tmplGenerator = &template.GeneratorConfig{Kind: genKind, Bytes: 32}
			genValue, genErr2 := core.GenerateValue(&core.GeneratorConfig{
				Kind:  tmplGenerator.Kind,
				Bytes: tmplGenerator.Bytes,
			})
			if genErr2 != nil {
				return nil, fmt.Errorf("generate secret: %w", genErr2)
			}
			tmplSecret = string(genValue)
			rotationMode = "generated"
			printSuccess("Generated new random %s secret for {{secret}}", genKind)
		case "keep":
			// Extract the password from the original connection string
			if strings.Contains(tmplString, "{{secret}}") {
				parts := strings.SplitN(connString, "://", 2)
				if len(parts) == 2 {
					afterScheme := parts[1]
					if atIdx := strings.Index(afterScheme, "@"); atIdx != -1 {
						userPass := afterScheme[:atIdx]
						if colonIdx := strings.Index(userPass, ":"); colonIdx != -1 {
							tmplSecret = userPass[colonIdx+1:]
						}
					}
				}
			}
			if tmplSecret == "" {
				printWarning("Could not extract password from connection string")
				var manualSecret string
				err = huh.NewInput().
					Title("Enter the secret value").
					EchoMode(huh.EchoModePassword).
					Value(&manualSecret).
					Run()
				if err != nil {
					return nil, err
				}
				tmplSecret = manualSecret
			}
			rotationMode = "external"
		case "enter":
			var manualSecret string
			err = huh.NewInput().
				Title("Enter the secret value").
				EchoMode(huh.EchoModePassword).
				Value(&manualSecret).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("secret cannot be empty")
					}
					return nil
				}).
				Run()
			if err != nil {
				return nil, err
			}
			tmplSecret = manualSecret
			rotationMode = "external"
		}

		// Compute final value for preview
		payload, payloadErr := template.NewPayload(tmplString, tmplValues, tmplSecret, tmplGenerator)
		if payloadErr != nil {
			return nil, fmt.Errorf("create template payload: %w", payloadErr)
		}
		value = []byte(payload.Computed)
		printSuccess("Computed key configured: %s", keyName)
	}

	return &keyInputData{
		keyName:       keyName,
		value:         value,
		rotationMode:  rotationMode,
		generator:     generator,
		isComputed:    isComputed,
		tmplString:    tmplString,
		tmplValues:    tmplValues,
		tmplSecret:    tmplSecret,
		tmplGenerator: tmplGenerator,
	}, nil
}

// addKeyToExistingSecret adds a new key to an existing secret interactively.
// This function handles the full flow: collect input, store to GSM, update metadata, reseal manifest.
func addKeyToExistingSecret(ctx context.Context, shortName string) error {
	cfg, err := resolveConfig()
	if err != nil {
		return fmt.Errorf("run 'waxseal setup' first: %w", err)
	}

	// Load metadata
	metadata, err := files.LoadMetadata(repoPath, shortName)
	if err != nil {
		return err
	}
	metadataPath := files.MetadataPath(repoPath, shortName)

	if metadata.IsRetired() {
		return fmt.Errorf("cannot add key to retired secret %q", shortName)
	}

	// Get existing key names
	existingKeys := make([]string, len(metadata.Keys))
	for i, k := range metadata.Keys {
		existingKeys[i] = k.KeyName
	}

	// Prompt for key name
	fmt.Println()
	fmt.Println(strings.Repeat("━", 64))
	fmt.Printf("%s➕ Add Key to %s%s\n", styleBold, shortName, styleReset)
	fmt.Println(strings.Repeat("━", 64))
	fmt.Println()

	var keyName string
	err = huh.NewInput().
		Title("Key name").
		Placeholder("e.g., password, api_key, db_url").
		Value(&keyName).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("key name is required")
			}
			for _, existing := range existingKeys {
				if existing == strings.TrimSpace(s) {
					return fmt.Errorf("key %q already exists", s)
				}
			}
			return nil
		}).
		Run()
	if err != nil {
		return err
	}
	keyName = strings.TrimSpace(keyName)

	// Collect key input
	keyData, err := collectSingleKeyInput(keyName, existingKeys)
	if err != nil {
		return err
	}
	if keyData == nil {
		return fmt.Errorf("cancelled")
	}

	// Show summary
	fmt.Println()
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("Adding key: %s/%s\n", shortName, keyName)
	mode := keyData.rotationMode
	if keyData.isComputed {
		mode = "computed"
	}
	fmt.Printf("  Mode: %s\n", mode)
	fmt.Println()

	if dryRun {
		printDim("[DRY RUN] Would add key — no changes made")
		return nil
	}

	proceed, err := confirm("Add this key?")
	if err != nil || !proceed {
		return fmt.Errorf("cancelled")
	}

	// Create GSM store
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	gsmResource := store.SecretResource(cfg.Store.ProjectID, store.FormatSecretID(shortName, keyName))

	var newKeyMeta core.KeyMetadata
	var newVersion string

	if keyData.isComputed {
		// Store JSON payload
		payload, payloadErr := template.NewPayload(keyData.tmplString, keyData.tmplValues, keyData.tmplSecret, keyData.tmplGenerator)
		if payloadErr != nil {
			return fmt.Errorf("create payload: %w", payloadErr)
		}
		payloadJSON, marshalErr := payload.Marshal()
		if marshalErr != nil {
			return fmt.Errorf("marshal payload: %w", marshalErr)
		}
		newVersion, err = gsmStore.CreateSecretVersion(ctx, gsmResource, payloadJSON)
		if err != nil {
			return fmt.Errorf("create GSM secret: %w", err)
		}
		printSuccess("Created computed GSM secret: %s (version %s)", keyName, newVersion)

		rotationCfg := &core.RotationConfig{Mode: keyData.rotationMode}
		if keyData.tmplGenerator != nil {
			rotationCfg.Generator = &core.GeneratorConfig{
				Kind:  keyData.tmplGenerator.Kind,
				Bytes: keyData.tmplGenerator.Bytes,
			}
		}
		newKeyMeta = core.KeyMetadata{
			KeyName:  keyName,
			Source:   core.SourceConfig{Kind: "computed"},
			Rotation: rotationCfg,
			Computed: &core.ComputedConfig{
				Kind:     "template",
				Template: keyData.tmplString,
				GSM: &core.GSMRef{
					SecretResource: gsmResource,
					Version:        newVersion,
				},
			},
		}
	} else {
		// Store raw value
		newVersion, err = gsmStore.CreateSecretVersion(ctx, gsmResource, keyData.value)
		if err != nil {
			return fmt.Errorf("create GSM secret: %w", err)
		}
		printSuccess("Created GSM secret: %s (version %s)", keyName, newVersion)

		newKeyMeta = core.KeyMetadata{
			KeyName: keyName,
			Source:  core.SourceConfig{Kind: "gsm"},
			GSM: &core.GSMRef{
				SecretResource: gsmResource,
				Version:        newVersion,
			},
			Rotation: &core.RotationConfig{
				Mode:      keyData.rotationMode,
				Generator: keyData.generator,
			},
		}
	}

	// Update metadata
	metadata.Keys = append(metadata.Keys, newKeyMeta)
	metadataYAML := files.SerializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	printSuccess("Updated metadata: %s", metadataPath)

	// Update SealedSecret manifest
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
		keyData.value,
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
	printSuccess("Key %s added to %s!", keyName, shortName)
	fmt.Println()

	return nil
}

// ── Create Secret Wizard ───────────────────────────────────────────────────

// createSecretInput holds all the form data for creating a new Secret.
type createSecretInput struct {
	shortName    string
	namespace    string
	manifestPath string
	scope        string
	secretType   string
}

// runCreateSecretWizard presents an interactive form to create a new Secret.
func runCreateSecretWizard(ctx context.Context) error {
	cfg, err := resolveConfig()
	if err != nil {
		return fmt.Errorf("run 'waxseal setup' first: %w", err)
	}

	// ── Step 1: Collect Secret details ─────────────────────────────────────
	fmt.Println()
	fmt.Println(strings.Repeat("━", 64))
	fmt.Printf("%s✨ Create a New Secret%s\n", styleBold, styleReset)
	fmt.Println(strings.Repeat("━", 64))
	fmt.Println()

	input := createSecretInput{
		namespace:  "default",
		scope:      "strict",
		secretType: "Opaque",
	}

	// Form for all required fields
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Secret name").
				Description("A short identifier (e.g., 'my-app-secrets')").
				Placeholder("my-app-secrets").
				Value(&input.shortName).
				Validate(func(s string) error {
					trimmed := strings.TrimSpace(s)
					if trimmed == "" {
						return fmt.Errorf("name is required")
					}
					if files.MetadataExists(repoPath, trimmed) {
						return fmt.Errorf("Secret %q already exists", trimmed)
					}
					return nil
				}),
			huh.NewInput().
				Title("Kubernetes namespace").
				Description("Where this Secret will be deployed").
				Placeholder("default").
				Value(&input.namespace).
				Validate(func(s string) error {
					trimmed := strings.TrimSpace(s)
					if trimmed == "" {
						return fmt.Errorf("namespace is required")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Manifest path").
				Description("Where to save the SealedSecret YAML file").
				Placeholder("apps/<name>/sealed-secret.yaml").
				Value(&input.manifestPath),
			huh.NewSelect[string]().
				Title("Sealing scope").
				Description("How tightly to bind the encrypted data").
				Options(
					huh.NewOption("Strict — bound to name + namespace (recommended)", "strict"),
					huh.NewOption("Namespace-wide — usable by any Secret in namespace", "namespace-wide"),
					huh.NewOption("Cluster-wide — usable anywhere in cluster", "cluster-wide"),
				).
				Value(&input.scope),
			huh.NewSelect[string]().
				Title("Secret type").
				Options(
					huh.NewOption("Opaque (generic)", "Opaque"),
					huh.NewOption("kubernetes.io/tls (TLS certificate)", "kubernetes.io/tls"),
					huh.NewOption("kubernetes.io/dockerconfigjson (Docker registry)", "kubernetes.io/dockerconfigjson"),
				).
				Value(&input.secretType),
		),
	).Run()
	if err != nil {
		return fmt.Errorf("cancelled: %w", err)
	}

	// Apply defaults and trim whitespace
	input.shortName = strings.TrimSpace(input.shortName)
	input.namespace = strings.TrimSpace(input.namespace)
	if input.manifestPath == "" {
		input.manifestPath = fmt.Sprintf("apps/%s/sealed-secret.yaml", input.shortName)
	}

	// ── Step 2: Add keys ───────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(strings.Repeat("─", 64))
	fmt.Printf("%s🔑 Add Keys%s\n", styleBold, styleReset)
	fmt.Println(strings.Repeat("─", 64))
	fmt.Println()
	printDim("Add at least one key. Press Enter with empty name to finish.")
	fmt.Println()

	var keys []keyInputData
	var existingKeyNames []string

	for {
		var keyName string
		err = huh.NewInput().
			Title("Key name").
			Description("Leave empty to finish adding keys").
			Placeholder("e.g., password, api_key, db_url").
			Value(&keyName).
			Run()
		if err != nil {
			return err
		}

		keyName = strings.TrimSpace(keyName)
		if keyName == "" {
			break
		}

		keyData, keyErr := collectSingleKeyInput(keyName, existingKeyNames)
		if keyErr != nil {
			return keyErr
		}
		if keyData == nil {
			continue // duplicate, already warned
		}

		keys = append(keys, *keyData)
		existingKeyNames = append(existingKeyNames, keyName)
	}

	if len(keys) == 0 {
		// Offer to create Secret without keys (they can add later)
		var createEmpty bool
		err = huh.NewConfirm().
			Title("No keys added. Create Secret anyway?").
			Description("You can add keys later with 'waxseal edit'").
			Value(&createEmpty).
			Run()
		if err != nil || !createEmpty {
			return fmt.Errorf("cancelled: at least one key is recommended")
		}
	}

	// ── Step 3: Show summary and confirm ───────────────────────────────────
	fmt.Println()
	fmt.Println(strings.Repeat("━", 64))
	fmt.Printf("%s📋 Summary%s\n", styleBold, styleReset)
	fmt.Println(strings.Repeat("━", 64))
	fmt.Println()
	fmt.Printf("  %sSecret:%s     %s\n", styleBold, styleReset, input.shortName)
	fmt.Printf("  %sNamespace:%s  %s\n", styleBold, styleReset, input.namespace)
	fmt.Printf("  %sManifest:%s   %s\n", styleBold, styleReset, input.manifestPath)
	fmt.Printf("  %sScope:%s      %s\n", styleBold, styleReset, input.scope)
	fmt.Printf("  %sType:%s       %s\n", styleBold, styleReset, input.secretType)
	fmt.Printf("  %sKeys:%s       %d\n", styleBold, styleReset, len(keys))
	for _, k := range keys {
		mode := k.rotationMode
		if k.generator != nil {
			mode = "generated"
		}
		if k.isComputed {
			mode = "computed"
		}
		fmt.Printf("                 • %s (%s)\n", k.keyName, mode)
	}
	fmt.Println()

	if dryRun {
		printDim("[DRY RUN] Would create Secret — no changes made")
		return nil
	}

	proceed, err := confirm("Create this Secret?")
	if err != nil || !proceed {
		return fmt.Errorf("cancelled")
	}

	// ── Step 4: Create everything ──────────────────────────────────────────
	fmt.Println()

	// Create GSM store
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	// Track created secrets for cleanup on failure
	var createdSecrets []string
	cleanup := func() {
		if len(createdSecrets) == 0 {
			return
		}
		printWarning("Cleaning up %d created GSM secret(s)...", len(createdSecrets))
		for _, resource := range createdSecrets {
			if delErr := gsmStore.DeleteSecret(ctx, resource); delErr != nil {
				logging.Warn("failed to cleanup secret", "resource", resource, "error", delErr)
			}
		}
	}

	// Create GSM secrets
	var keyMetadata []core.KeyMetadata
	for _, k := range keys {
		gsmResource := store.SecretResource(cfg.Store.ProjectID, store.FormatSecretID(input.shortName, k.keyName))

		var version string
		var gsmErr error

		if k.isComputed {
			// For computed keys, store JSON payload in GSM
			payload, payloadErr := template.NewPayload(k.tmplString, k.tmplValues, k.tmplSecret, k.tmplGenerator)
			if payloadErr != nil {
				cleanup()
				return fmt.Errorf("create payload for %s: %w", k.keyName, payloadErr)
			}
			payloadJSON, marshalErr := payload.Marshal()
			if marshalErr != nil {
				cleanup()
				return fmt.Errorf("marshal payload for %s: %w", k.keyName, marshalErr)
			}
			version, gsmErr = gsmStore.CreateSecretVersion(ctx, gsmResource, payloadJSON)
			if gsmErr != nil {
				cleanup()
				return fmt.Errorf("create GSM secret %s: %w", k.keyName, gsmErr)
			}
			createdSecrets = append(createdSecrets, gsmResource)
			printSuccess("Created computed GSM secret: %s (version %s)", k.keyName, version)

			// Build computed key metadata
			rotationCfg := &core.RotationConfig{
				Mode: k.rotationMode,
			}
			if k.tmplGenerator != nil {
				rotationCfg.Generator = &core.GeneratorConfig{
					Kind:  k.tmplGenerator.Kind,
					Bytes: k.tmplGenerator.Bytes,
				}
			}
			keyMetadata = append(keyMetadata, core.KeyMetadata{
				KeyName:  k.keyName,
				Source:   core.SourceConfig{Kind: "computed"},
				Rotation: rotationCfg,
				Computed: &core.ComputedConfig{
					Kind:     "template",
					Template: k.tmplString,
					GSM: &core.GSMRef{
						SecretResource: gsmResource,
						Version:        version,
					},
				},
			})
		} else {
			// For regular keys, store raw value
			version, gsmErr = gsmStore.CreateSecretVersion(ctx, gsmResource, k.value)
			if gsmErr != nil {
				cleanup()
				return fmt.Errorf("create GSM secret %s: %w", k.keyName, gsmErr)
			}
			createdSecrets = append(createdSecrets, gsmResource)
			printSuccess("Created GSM secret: %s (version %s)", k.keyName, version)

			keyMetadata = append(keyMetadata, core.KeyMetadata{
				KeyName: k.keyName,
				Source:  core.SourceConfig{Kind: "gsm"},
				GSM: &core.GSMRef{
					SecretResource: gsmResource,
					Version:        version,
				},
				Rotation: &core.RotationConfig{
					Mode:      k.rotationMode,
					Generator: k.generator,
				},
			})
		}
	}

	// Create metadata
	metadata := &core.SecretMetadata{
		ShortName:    input.shortName,
		ManifestPath: input.manifestPath,
		SealedSecret: core.SealedSecretRef{
			Name:      input.shortName,
			Namespace: input.namespace,
			Scope:     input.scope,
			Type:      input.secretType,
		},
		Status: "active",
		Keys:   keyMetadata,
	}

	// Save metadata
	metadataPath := files.MetadataPath(repoPath, input.shortName)
	metadataYAML := files.SerializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	printSuccess("Created metadata: %s", metadataPath)

	// Create SealedSecret manifest (only if we have keys)
	if len(keys) > 0 {
		sealer := resolveSealer(cfg)
		encryptedData := make(map[string]string)

		for _, k := range keys {
			encrypted, err := sealer.Seal(input.shortName, input.namespace, k.keyName, k.value, input.scope)
			if err != nil {
				return fmt.Errorf("seal key %s: %w", k.keyName, err)
			}
			encryptedData[k.keyName] = encrypted
		}

		sealedSecret := seal.NewSealedSecret(input.shortName, input.namespace, input.scope, input.secretType, encryptedData)
		manifestBytes, err := sealedSecret.ToYAML()
		if err != nil {
			return fmt.Errorf("serialize SealedSecret: %w", err)
		}

		manifestFullPath := filepath.Join(repoPath, input.manifestPath)
		writer := files.NewAtomicWriter(files.YAMLKindValidator("SealedSecret"))
		if err := writer.Write(manifestFullPath, manifestBytes); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		printSuccess("Created manifest: %s", manifestFullPath)
	}

	// ── Done ───────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(strings.Repeat("━", 64))
	printSuccess("Secret %s created successfully!", input.shortName)
	fmt.Println(strings.Repeat("━", 64))
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Commit: git add %s %s\n", metadataPath, input.manifestPath)
	fmt.Println("  2. Push to trigger GitOps sync, or apply manually")
	fmt.Println()

	return nil
}
