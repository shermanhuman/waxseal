package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/logging"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
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
		return runEditWithAction("addkey")
	},
}

var editUpdatekeyCmd = &cobra.Command{
	Use:   "updatekey",
	Short: "Interactive update-key wizard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditWithAction("updatekey")
	},
}

var editRetirekeyCmd = &cobra.Command{
	Use:   "retirekey",
	Short: "Interactive retire-key wizard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditWithAction("retirekey")
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
func dispatch(action string, metadata *core.SecretMetadata) error {
	switch action {
	case "addkey":
		return addCmd.RunE(addCmd, []string{metadata.ShortName})

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
	return dispatch(action, metadata)
}

// runEditWithAction is used by edit subcommands — picks a Secret, then runs the action.
func runEditWithAction(action string) error {
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
			// Prompt for Secret name instead of hardcoding
			var name string
			err := huh.NewInput().
				Title("No Secrets registered. Enter a name for the new Secret:").
				Value(&name).
				Run()
			if err != nil || strings.TrimSpace(name) == "" {
				return fmt.Errorf("cancelled")
			}
			return addCmd.RunE(addCmd, []string{strings.TrimSpace(name)})
		}
		return fmt.Errorf("no eligible Secrets for %s", action)
	}

	return dispatch(action, metadata)
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

	type keyInput struct {
		keyName      string
		value        []byte
		rotationMode string
		generator    *core.GeneratorConfig
	}
	var keys []keyInput

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

		// Check for duplicate
		duplicate := false
		for _, k := range keys {
			if k.keyName == keyName {
				printWarning("Key %q already added, skipping", keyName)
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}

		// Value source
		var valueSource string
		err = huh.NewSelect[string]().
			Title(fmt.Sprintf("Value for '%s'", keyName)).
			Options(
				huh.NewOption("🎲 Generate random (32 bytes, base64)", "random"),
				huh.NewOption("✏️  Enter value now (masked)", "enter"),
			).
			Value(&valueSource).
			Run()
		if err != nil {
			return err
		}

		var value []byte
		var rotationMode string
		var generator *core.GeneratorConfig

		switch valueSource {
		case "random":
			generator = &core.GeneratorConfig{Kind: "randomBase64", Bytes: 32}
			value, err = core.GenerateValue(generator)
			if err != nil {
				return fmt.Errorf("generate random value: %w", err)
			}
			rotationMode = "generated"
			printSuccess("Generated random value for %s", keyName)

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
				return err
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
				return err
			}
		}

		keys = append(keys, keyInput{
			keyName:      keyName,
			value:        value,
			rotationMode: rotationMode,
			generator:    generator,
		})
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
		version, err := gsmStore.CreateSecretVersion(ctx, gsmResource, k.value)
		if err != nil {
			cleanup()
			return fmt.Errorf("create GSM secret %s: %w", k.keyName, err)
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
	metadataYAML := serializeMetadata(metadata)
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
