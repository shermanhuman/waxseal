package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit [shortName]",
	Short: "Interactively add, update, or retire keys",
	Long: `Interactive wizard for managing secret keys.

Without arguments, presents a secret picker then an action menu.
With a shortName, jumps directly to the action menu for that secret.

Actions:
  addkey     - Add a new key to the secret
  updatekey  - Update an existing key's value
  retirekey  - Mark the secret as retired

Examples:
  # Interactive: pick secret, then pick action
  waxseal edit

  # Interactive: pick action for a specific secret
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
}

// ── Shared helpers ─────────────────────────────────────────────────────────

// pickSecret presents a TUI secret picker and returns the selected metadata.
// Returns nil, nil if no secrets are registered.
func pickSecret(title string, filter func(*core.SecretMetadata) bool) (*core.SecretMetadata, error) {
	allSecrets, _ := files.LoadAllMetadataCollectErrors(repoPath)
	if len(allSecrets) == 0 {
		return nil, nil
	}

	// Build options: active first, retired last
	var activeOpts, retiredOpts []huh.Option[string]
	lookup := make(map[string]*core.SecretMetadata)
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

	options := append(activeOpts, retiredOpts...)
	if len(options) == 0 {
		return nil, nil
	}

	var shortName string
	err := huh.NewSelect[string]().
		Title(title).
		Options(options...).
		Value(&shortName).
		Run()
	if err != nil {
		return nil, fmt.Errorf("selection cancelled: %w", err)
	}

	return lookup[shortName], nil
}

// pickAction presents the action menu for a loaded secret.
func pickAction(metadata *core.SecretMetadata) (string, error) {
	// Show context
	fmt.Printf("\n  Secret: %s\n", metadata.ShortName)
	fmt.Printf("  Status: %s\n", statusLabel(metadata.Status))
	fmt.Printf("  Keys:   %s\n", keysSummary(metadata.Keys))
	fmt.Println()

	var actions []huh.Option[string]
	if metadata.IsRetired() {
		actions = []huh.Option[string]{
			huh.NewOption("View metadata", "view"),
		}
	} else {
		actions = []huh.Option[string]{
			huh.NewOption("Add a new key", "addkey"),
			huh.NewOption("Update an existing key", "updatekey"),
			huh.NewOption("Retire this secret", "retirekey"),
			huh.NewOption("View metadata", "view"),
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
func dispatch(action string, metadata *core.SecretMetadata) error {
	switch action {
	case "addkey":
		return addCmd.RunE(addCmd, []string{metadata.ShortName})

	case "updatekey":
		if len(metadata.Keys) == 0 {
			return fmt.Errorf("secret %q has no keys", metadata.ShortName)
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
	var metadata *core.SecretMetadata
	var err error

	if len(args) == 1 {
		// Load the named secret directly
		metadata, err = files.LoadMetadata(repoPath, args[0])
		if err != nil {
			return fmt.Errorf("secret %q not found: %w", args[0], err)
		}
	} else {
		metadata, err = pickSecret("Select a secret to edit", nil)
		if err != nil {
			return err
		}
		if metadata == nil {
			fmt.Println("No secrets registered. Use 'waxseal addkey' to create one.")
			return nil
		}
	}

	action, err := pickAction(metadata)
	if err != nil {
		return err
	}
	return dispatch(action, metadata)
}

// runEditWithAction is used by edit subcommands — picks a secret, then runs the action.
func runEditWithAction(action string) error {
	filter := func(s *core.SecretMetadata) bool {
		if action == "retirekey" {
			return !s.IsRetired()
		}
		return true
	}

	metadata, err := pickSecret(fmt.Sprintf("Select a secret to %s", action), filter)
	if err != nil {
		return err
	}
	if metadata == nil {
		if action == "addkey" {
			fmt.Println("No secrets registered. Creating a new one...")
			return addCmd.RunE(addCmd, []string{"new-secret"})
		}
		return fmt.Errorf("no eligible secrets for %s", action)
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
