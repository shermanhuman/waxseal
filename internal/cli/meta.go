package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// ── Parent: waxseal meta ───────────────────────────────────────────────────

var metaCmd = &cobra.Command{
	Use:   "meta",
	Short: "View secret metadata (list, showkey)",
	Long: `View secret metadata without modifying anything.

Subcommands:
  waxseal meta list secrets            List all registered secrets
  waxseal meta list keys <shortName>   List keys within a secret
  waxseal meta showkey <shortName>     Display detailed metadata for a secret`,
}

// ── waxseal meta list ──────────────────────────────────────────────────────

var metaListCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets or keys",
	Long: `List registered secrets or keys within a secret.

  waxseal meta list secrets            List all registered secrets
  waxseal meta list keys <shortName>   List keys within a secret

Running "waxseal meta list" without a subcommand defaults to "list secrets".`,
	RunE: runMetaListSecrets, // default to listing secrets
}

// ── waxseal meta list secrets ──────────────────────────────────────────────

var metaListSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List registered secrets and their status",
	Long: `List all secrets registered in .waxseal/metadata/.

Shows shortName, status, key count, rotation modes, and expiration status.

Examples:
  waxseal meta list secrets
  waxseal meta list secrets -o json`,
	RunE: runMetaListSecrets,
}

// ── waxseal meta list keys ─────────────────────────────────────────────────

var metaListKeysCmd = &cobra.Command{
	Use:   "keys <shortName>",
	Short: "List keys within a secret",
	Long: `List all keys within a specific secret, showing their names,
rotation modes, source kinds, and expiration status.

Examples:
  waxseal meta list keys my-app-secrets
  waxseal meta list keys my-app-secrets -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runMetaListKeys,
}

// ── waxseal meta showkey ───────────────────────────────────────────────────

var metaShowKeyCmd = &cobra.Command{
	Use:   "showkey <shortName>",
	Short: "Display detailed secret metadata",
	Long: `Display metadata for a registered secret without showing actual values.

Shows:
  - Status (active/retired)
  - Namespace and name
  - All keys with their rotation modes
  - Expiry dates if configured
  - GSM resource references

Examples:
  waxseal meta showkey my-app-secrets
  waxseal meta showkey my-app-secrets --json
  waxseal meta showkey my-app-secrets --yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runMetaShowKey,
}

var (
	showKeyOutputJSON bool
	showKeyOutputYAML bool
)

func init() {
	rootCmd.AddCommand(metaCmd)
	metaCmd.AddCommand(metaListCmd)
	metaCmd.AddCommand(metaShowKeyCmd)
	metaListCmd.AddCommand(metaListSecretsCmd)
	metaListCmd.AddCommand(metaListKeysCmd)

	// Flags
	metaListCmd.PersistentFlags().StringP("output", "o", "table", "Output format: table, json")
	metaShowKeyCmd.Flags().BoolVar(&showKeyOutputJSON, "json", false, "Output as JSON")
	metaShowKeyCmd.Flags().BoolVar(&showKeyOutputYAML, "yaml", false, "Output as YAML")

	// Metadata checks
	addMetadataCheck(metaListCmd)
	addMetadataCheck(metaShowKeyCmd)
}

// ── list secrets ───────────────────────────────────────────────────────────

func runMetaListSecrets(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")

	secrets, err := files.LoadAllMetadata(repoPath)
	if err != nil {
		if core.IsNotFound(err) {
			fmt.Println("No secrets registered. Run 'waxseal discover' first.")
			return nil
		}
		return err
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets registered. Run 'waxseal discover' first.")
		return nil
	}

	if output == "json" {
		return printListSecretsJSON(secrets)
	}

	return printListSecretsTable(secrets)
}

func printListSecretsTable(secrets []*core.SecretMetadata) error {
	fmt.Printf("%-25s %-10s %-6s %-30s %-20s\n", "SHORT NAME", "STATUS", "KEYS", "ROTATION MODES", "EXPIRY")
	fmt.Println(strings.Repeat("-", 95))

	for _, s := range secrets {
		status := s.Status
		if status == "" {
			status = "active"
		}

		modes := make(map[string]bool)
		for _, k := range s.Keys {
			if k.Rotation != nil {
				modes[k.Rotation.Mode] = true
			} else if k.Source.Kind == "computed" {
				modes["computed"] = true
			}
		}
		modeList := make([]string, 0, len(modes))
		for m := range modes {
			modeList = append(modeList, m)
		}

		expiry := ""
		if s.IsExpired() {
			expiry = "EXPIRED"
		} else if s.ExpiresWithinDays(30) {
			expiry = "expiring soon"
		}

		fmt.Printf("%-25s %-10s %-6d %-30s %-20s\n",
			truncateStr(s.ShortName, 25),
			status,
			len(s.Keys),
			truncateStr(strings.Join(modeList, ", "), 30),
			expiry,
		)
	}

	return nil
}

func printListSecretsJSON(secrets []*core.SecretMetadata) error {
	fmt.Println("[")
	for i, s := range secrets {
		status := s.Status
		if status == "" {
			status = "active"
		}

		expired := s.IsExpired()
		expiringSoon := s.ExpiresWithinDays(30)

		comma := ","
		if i == len(secrets)-1 {
			comma = ""
		}

		fmt.Printf(`  {"shortName": %q, "status": %q, "keyCount": %d, "expired": %v, "expiringSoon": %v}%s
`,
			s.ShortName, status, len(s.Keys), expired, expiringSoon, comma)
	}
	fmt.Println("]")
	return nil
}

// ── list keys ──────────────────────────────────────────────────────────────

func runMetaListKeys(cmd *cobra.Command, args []string) error {
	shortName := args[0]
	output, _ := cmd.Flags().GetString("output")

	metadata, err := files.LoadMetadata(repoPath, shortName)
	if err != nil {
		return err
	}

	if output == "json" {
		return printListKeysJSON(metadata)
	}

	return printListKeysTable(metadata)
}

func printListKeysTable(metadata *core.SecretMetadata) error {
	fmt.Printf("Keys in %s (%d total):\n\n", metadata.ShortName, len(metadata.Keys))
	fmt.Printf("%-35s %-12s %-12s %-20s\n", "KEY NAME", "SOURCE", "ROTATION", "EXPIRY")
	fmt.Println(strings.Repeat("-", 82))

	for _, k := range metadata.Keys {
		source := k.Source.Kind
		if source == "" {
			source = "unknown"
		}

		rotation := "—"
		if k.Rotation != nil && k.Rotation.Mode != "" {
			rotation = k.Rotation.Mode
		}

		expiry := "—"
		if k.Expiry != nil && k.Expiry.ExpiresAt != "" {
			expTime, err := time.Parse(time.RFC3339, k.Expiry.ExpiresAt)
			if err == nil {
				daysLeft := int(time.Until(expTime).Hours() / 24)
				if daysLeft < 0 {
					expiry = fmt.Sprintf("EXPIRED (%dd ago)", -daysLeft)
				} else {
					expiry = fmt.Sprintf("%dd remaining", daysLeft)
				}
			}
		}

		fmt.Printf("%-35s %-12s %-12s %-20s\n",
			truncateStr(k.KeyName, 35), source, rotation, expiry)
	}

	return nil
}

func printListKeysJSON(metadata *core.SecretMetadata) error {
	type keyJSON struct {
		KeyName      string `json:"keyName"`
		SourceKind   string `json:"sourceKind"`
		RotationMode string `json:"rotationMode,omitempty"`
		ExpiresAt    string `json:"expiresAt,omitempty"`
	}

	keys := make([]keyJSON, 0, len(metadata.Keys))
	for _, k := range metadata.Keys {
		kj := keyJSON{
			KeyName:    k.KeyName,
			SourceKind: k.Source.Kind,
		}
		if k.Rotation != nil {
			kj.RotationMode = k.Rotation.Mode
		}
		if k.Expiry != nil {
			kj.ExpiresAt = k.Expiry.ExpiresAt
		}
		keys = append(keys, kj)
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// ── showkey ────────────────────────────────────────────────────────────────

func runMetaShowKey(cmd *cobra.Command, args []string) error {
	shortName := args[0]

	metadata, err := files.LoadMetadata(repoPath, shortName)
	if err != nil {
		return err
	}

	if showKeyOutputJSON {
		return outputShowKeyJSON(metadata)
	}
	if showKeyOutputYAML {
		return outputShowKeyYAML(metadata)
	}

	return outputShowKeyHuman(metadata)
}

type showKeyOutput struct {
	ShortName    string             `json:"shortName" yaml:"shortName"`
	Status       string             `json:"status" yaml:"status"`
	Namespace    string             `json:"namespace" yaml:"namespace"`
	Name         string             `json:"name" yaml:"name"`
	ManifestPath string             `json:"manifestPath" yaml:"manifestPath"`
	Keys         []showKeyEntryJSON `json:"keys" yaml:"keys"`
}

type showKeyEntryJSON struct {
	KeyName      string `json:"keyName" yaml:"keyName"`
	RotationMode string `json:"rotationMode,omitempty" yaml:"rotationMode,omitempty"`
	Expiry       string `json:"expiry,omitempty" yaml:"expiry,omitempty"`
	GSMResource  string `json:"gsmResource,omitempty" yaml:"gsmResource,omitempty"`
	GSMVersion   string `json:"gsmVersion,omitempty" yaml:"gsmVersion,omitempty"`
}

func buildShowKeyOutput(metadata *core.SecretMetadata) showKeyOutput {
	output := showKeyOutput{
		ShortName:    metadata.ShortName,
		Status:       metadata.Status,
		Namespace:    metadata.SealedSecret.Namespace,
		Name:         metadata.SealedSecret.Name,
		ManifestPath: metadata.ManifestPath,
		Keys:         make([]showKeyEntryJSON, 0, len(metadata.Keys)),
	}

	for _, key := range metadata.Keys {
		keyOut := showKeyEntryJSON{
			KeyName: key.KeyName,
		}
		if key.Rotation != nil {
			keyOut.RotationMode = key.Rotation.Mode
		}
		if key.Expiry != nil && key.Expiry.ExpiresAt != "" {
			keyOut.Expiry = key.Expiry.ExpiresAt
		}
		if key.GSM != nil {
			keyOut.GSMResource = key.GSM.SecretResource
			keyOut.GSMVersion = key.GSM.Version
		}
		output.Keys = append(output.Keys, keyOut)
	}

	return output
}

func outputShowKeyJSON(metadata *core.SecretMetadata) error {
	output := buildShowKeyOutput(metadata)
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputShowKeyYAML(metadata *core.SecretMetadata) error {
	output := buildShowKeyOutput(metadata)
	data, err := yaml.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

func outputShowKeyHuman(metadata *core.SecretMetadata) error {
	statusIcon := "●"
	if metadata.IsRetired() {
		statusIcon = "○"
	}

	fmt.Printf("%s %s\n", statusIcon, metadata.ShortName)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  Status:       %s\n", metadata.Status)
	fmt.Printf("  Namespace:    %s\n", metadata.SealedSecret.Namespace)
	fmt.Printf("  Name:         %s\n", metadata.SealedSecret.Name)
	fmt.Printf("  Manifest:     %s\n", metadata.ManifestPath)

	if metadata.IsRetired() {
		if metadata.RetireReason != "" || metadata.ReplacedBy != "" {
			fmt.Println()
			fmt.Println("  Retired:")
			if metadata.RetireReason != "" {
				fmt.Printf("    Reason:      %s\n", metadata.RetireReason)
			}
			if metadata.ReplacedBy != "" {
				fmt.Printf("    Replaced by: %s\n", metadata.ReplacedBy)
			}
		}
	}

	fmt.Println()
	fmt.Printf("  Keys (%d):\n", len(metadata.Keys))
	for _, key := range metadata.Keys {
		mode := "unknown"
		if key.Rotation != nil && key.Rotation.Mode != "" {
			mode = key.Rotation.Mode
		}

		expiryStr := ""
		if key.Expiry != nil && key.Expiry.ExpiresAt != "" {
			expTime, err := time.Parse(time.RFC3339, key.Expiry.ExpiresAt)
			if err == nil {
				daysLeft := int(time.Until(expTime).Hours() / 24)
				if daysLeft < 0 {
					expiryStr = fmt.Sprintf(" (EXPIRED %d days ago)", -daysLeft)
				} else if daysLeft < 30 {
					expiryStr = fmt.Sprintf(" (expires in %d days)", daysLeft)
				}
			}
		}

		fmt.Printf("    • %s [%s]%s\n", key.KeyName, mode, expiryStr)

		if key.GSM != nil {
			fmt.Printf("      GSM: %s@%s\n", key.GSM.SecretResource, key.GSM.Version)
		}
	}

	return nil
}
