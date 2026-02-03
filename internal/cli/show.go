package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var showCmd = &cobra.Command{
	Use:   "show <shortName>",
	Short: "Display secret metadata",
	Long: `Display metadata for a registered secret without showing actual values.

Shows:
  - Status (active/retired)
  - Namespace and name
  - All keys with their rotation modes
  - Expiry dates if configured
  - GSM resource references

Examples:
  waxseal show my-app-secrets
  waxseal show my-app-secrets --json
  waxseal show my-app-secrets --yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runShow,
}

var (
	showOutputJSON bool
	showOutputYAML bool
)

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.Flags().BoolVar(&showOutputJSON, "json", false, "Output as JSON")
	showCmd.Flags().BoolVar(&showOutputYAML, "yaml", false, "Output as YAML")
}

func runShow(cmd *cobra.Command, args []string) error {
	shortName := args[0]

	// Load metadata
	metadataPath := filepath.Join(repoPath, ".waxseal", "metadata", shortName+".yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("secret %q not found", shortName)
		}
		return fmt.Errorf("read metadata: %w", err)
	}

	metadata, err := core.ParseMetadata(data)
	if err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	// Output format
	if showOutputJSON {
		return outputShowJSON(metadata)
	}
	if showOutputYAML {
		return outputShowYAML(metadata)
	}

	// Human-readable format
	return outputShowHuman(metadata)
}

func outputShowJSON(metadata *core.SecretMetadata) error {
	output := buildShowOutput(metadata)
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputShowYAML(metadata *core.SecretMetadata) error {
	output := buildShowOutput(metadata)
	data, err := yaml.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

type showOutput struct {
	ShortName    string          `json:"shortName" yaml:"shortName"`
	Status       string          `json:"status" yaml:"status"`
	Namespace    string          `json:"namespace" yaml:"namespace"`
	Name         string          `json:"name" yaml:"name"`
	ManifestPath string          `json:"manifestPath" yaml:"manifestPath"`
	Keys         []showKeyOutput `json:"keys" yaml:"keys"`
}

type showKeyOutput struct {
	KeyName      string `json:"keyName" yaml:"keyName"`
	RotationMode string `json:"rotationMode,omitempty" yaml:"rotationMode,omitempty"`
	Expiry       string `json:"expiry,omitempty" yaml:"expiry,omitempty"`
	GSMResource  string `json:"gsmResource,omitempty" yaml:"gsmResource,omitempty"`
	GSMVersion   string `json:"gsmVersion,omitempty" yaml:"gsmVersion,omitempty"`
}

func buildShowOutput(metadata *core.SecretMetadata) showOutput {
	output := showOutput{
		ShortName:    metadata.ShortName,
		Status:       metadata.Status,
		Namespace:    metadata.SealedSecret.Namespace,
		Name:         metadata.SealedSecret.Name,
		ManifestPath: metadata.ManifestPath,
		Keys:         make([]showKeyOutput, 0, len(metadata.Keys)),
	}

	for _, key := range metadata.Keys {
		keyOut := showKeyOutput{
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

func outputShowHuman(metadata *core.SecretMetadata) error {
	// Status indicator
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
