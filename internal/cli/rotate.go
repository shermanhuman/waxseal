package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/reseal"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate <shortName> [keyName]",
	Short: "Rotate secret values and reseal",
	Long: `Rotate secret values by generating new versions in GSM, then reseal.

For keys with rotation.mode=generated:
  - Generates a new random value based on the generator config
  - Adds a new version to GSM
  - Updates metadata with new version number
  - Reseals the manifest

For keys with rotation.mode=external or manual:
  - Displays operator hints if available
  - Waits for confirmation that the value has been updated externally
  - Updates metadata with new version number
  - Reseals the manifest

Examples:
  # Rotate a specific key
  waxseal rotate my-app-secrets password

  # Rotate all generated keys in a secret
  waxseal rotate my-app-secrets --generated

Exit codes:
  0 - Success
  2 - Failed`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runRotate,
}

var rotateGenerated bool

func init() {
	rootCmd.AddCommand(rotateCmd)
	rotateCmd.Flags().BoolVar(&rotateGenerated, "generated", false, "Rotate all keys with mode=generated")
}

func runRotate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shortName := args[0]

	var keyName string
	if len(args) > 1 {
		keyName = args[1]
	}

	// Load config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

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

	if metadata.IsRetired() {
		return fmt.Errorf("cannot rotate retired secret %q", shortName)
	}

	// Create store
	var secretStore store.Store
	if cfg.Store.Kind == "gsm" {
		gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
		if err != nil {
			return fmt.Errorf("create GSM store: %w", err)
		}
		defer gsmStore.Close()
		secretStore = gsmStore
	} else {
		return fmt.Errorf("unsupported store kind: %s", cfg.Store.Kind)
	}

	// Find keys to rotate
	var keysToRotate []core.KeyMetadata
	for _, k := range metadata.Keys {
		if k.Source.Kind != "gsm" {
			continue // Skip computed keys
		}

		if keyName != "" && k.KeyName == keyName {
			keysToRotate = append(keysToRotate, k)
			break
		}

		if rotateGenerated && k.Rotation != nil && k.Rotation.Mode == "generated" {
			keysToRotate = append(keysToRotate, k)
		}
	}

	if len(keysToRotate) == 0 {
		if keyName != "" {
			return fmt.Errorf("key %q not found in secret %q", keyName, shortName)
		}
		fmt.Println("No keys to rotate. Use --generated or specify a key name.")
		return nil
	}

	// Rotate each key
	metadataUpdated := false
	for i, key := range keysToRotate {
		fmt.Printf("\nRotating %s/%s...\n", shortName, key.KeyName)

		if key.Rotation == nil {
			fmt.Printf("  Skipping: no rotation config\n")
			continue
		}

		var newValue []byte
		var err error

		switch key.Rotation.Mode {
		case "generated":
			newValue, err = generateValue(key.Rotation.Generator)
			if err != nil {
				return fmt.Errorf("generate value for %s: %w", key.KeyName, err)
			}
			fmt.Printf("  Generated new value (%d bytes)\n", len(newValue))

		case "external", "manual":
			fmt.Printf("  Mode: %s\n", key.Rotation.Mode)
			if key.OperatorHints != nil {
				displayOperatorHints(key.OperatorHints, key.KeyName)
			}
			fmt.Println("  Please update the value externally, then press Enter to continue...")
			if !dryRun && !yes {
				fmt.Scanln()
			}
			// For external/manual, we don't generate - we expect GSM to have been updated
			// Just increment version reference
			continue

		case "unknown":
			fmt.Printf("  Skipping: rotation mode is 'unknown' - update metadata first\n")
			continue

		default:
			fmt.Printf("  Skipping: unsupported rotation mode %q\n", key.Rotation.Mode)
			continue
		}

		if dryRun {
			fmt.Printf("  [DRY RUN] Would add new version to GSM\n")
			continue
		}

		// Add new version to GSM
		newVersion, err := secretStore.AddVersion(ctx, key.GSM.SecretResource, newValue)
		if err != nil {
			return fmt.Errorf("add GSM version for %s: %w", key.KeyName, err)
		}
		fmt.Printf("  Added GSM version: %s\n", newVersion)

		// Update metadata with new version
		metadata.Keys[i].GSM.Version = newVersion
		metadataUpdated = true
	}

	if !metadataUpdated {
		fmt.Println("\nNo values rotated.")
		return nil
	}

	// Write updated metadata
	if !dryRun {
		updatedMetadata := serializeMetadata(metadata)
		if err := os.WriteFile(metadataPath, []byte(updatedMetadata), 0o644); err != nil {
			return fmt.Errorf("write metadata: %w", err)
		}
		fmt.Printf("\n✓ Updated metadata: %s\n", metadataPath)
	}

	// Reseal
	fmt.Println("\nResealing...")

	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}
	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	engine := reseal.NewEngine(secretStore, sealer, repoPath, dryRun)
	result, err := engine.ResealOne(ctx, shortName)
	if err != nil {
		return fmt.Errorf("reseal: %w", err)
	}

	if result.DryRun {
		fmt.Printf("✓ Would reseal %d keys [DRY RUN]\n", result.KeysResealed)
	} else {
		fmt.Printf("✓ Resealed %d keys\n", result.KeysResealed)
	}

	return nil
}

func generateValue(gen *core.GeneratorConfig) ([]byte, error) {
	if gen == nil {
		return nil, fmt.Errorf("no generator config")
	}

	// Determine byte count
	byteCount := gen.Bytes
	if byteCount == 0 && gen.Chars > 0 {
		// For base64, each 3 bytes = 4 chars
		byteCount = (gen.Chars * 3) / 4
		if byteCount < 1 {
			byteCount = 1
		}
	}
	if byteCount == 0 {
		byteCount = 32 // Default to 32 bytes
	}

	// Generate random bytes
	randomBytes := make([]byte, byteCount)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}

	// Encode based on kind
	switch gen.Kind {
	case "randomBase64":
		return []byte(base64.StdEncoding.EncodeToString(randomBytes)), nil
	case "randomHex":
		return []byte(hex.EncodeToString(randomBytes)), nil
	case "randomBytes":
		return randomBytes, nil
	default:
		return nil, fmt.Errorf("unsupported generator kind: %s", gen.Kind)
	}
}

// displayOperatorHints prints operator hints for manual rotation.
// Per plan: hints content is stored in GSM, metadata only has the reference.
func displayOperatorHints(hints *core.OperatorHints, keyName string) {
	fmt.Printf("\n  ┌─ Operator Hints for %s ─\n", keyName)
	if hints.GSM != nil && hints.GSM.SecretResource != "" {
		fmt.Printf("  │ Hints stored in GSM:\n")
		fmt.Printf("  │   %s (version: %s)\n", hints.GSM.SecretResource, hints.GSM.Version)
		fmt.Printf("  │\n")
		fmt.Printf("  │ To view hints:\n")
		fmt.Printf("  │   gcloud secrets versions access %s --secret=%s\n",
			hints.GSM.Version,
			// Extract secret name from resource path (last segment)
			hints.GSM.SecretResource[len("projects/")+strings.Index(hints.GSM.SecretResource[len("projects/"):], "/secrets/")+len("/secrets/"):])
	} else {
		fmt.Printf("  │ No GSM hints reference configured.\n")
		fmt.Printf("  │ Consult documentation or team for rotation guidance.\n")
	}
	fmt.Printf("  └────────────────────────────\n\n")
}

func serializeMetadata(m *core.SecretMetadata) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("shortName: %s\n", m.ShortName))
	sb.WriteString(fmt.Sprintf("manifestPath: %s\n", m.ManifestPath))
	sb.WriteString("sealedSecret:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", m.SealedSecret.Name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", m.SealedSecret.Namespace))
	sb.WriteString(fmt.Sprintf("  scope: %s\n", m.SealedSecret.Scope))
	if m.SealedSecret.Type != "" {
		sb.WriteString(fmt.Sprintf("  type: %s\n", m.SealedSecret.Type))
	}
	if m.Status != "" {
		sb.WriteString(fmt.Sprintf("status: %s\n", m.Status))
	}
	if m.RetiredAt != "" {
		sb.WriteString(fmt.Sprintf("retiredAt: %s\n", m.RetiredAt))
	}
	if m.RetireReason != "" {
		sb.WriteString(fmt.Sprintf("retireReason: %s\n", m.RetireReason))
	}
	if m.ReplacedBy != "" {
		sb.WriteString(fmt.Sprintf("replacedBy: %s\n", m.ReplacedBy))
	}

	sb.WriteString("keys:\n")
	for _, k := range m.Keys {
		sb.WriteString(fmt.Sprintf("  - keyName: %s\n", k.KeyName))
		sb.WriteString("    source:\n")
		sb.WriteString(fmt.Sprintf("      kind: %s\n", k.Source.Kind))

		if k.GSM != nil {
			sb.WriteString("    gsm:\n")
			sb.WriteString(fmt.Sprintf("      secretResource: %s\n", k.GSM.SecretResource))
			sb.WriteString(fmt.Sprintf("      version: \"%s\"\n", k.GSM.Version))
		}

		if k.Rotation != nil {
			sb.WriteString("    rotation:\n")
			sb.WriteString(fmt.Sprintf("      mode: %s\n", k.Rotation.Mode))
			if k.Rotation.Generator != nil {
				sb.WriteString("      generator:\n")
				sb.WriteString(fmt.Sprintf("        kind: %s\n", k.Rotation.Generator.Kind))
				if k.Rotation.Generator.Bytes > 0 {
					sb.WriteString(fmt.Sprintf("        bytes: %d\n", k.Rotation.Generator.Bytes))
				}
				if k.Rotation.Generator.Chars > 0 {
					sb.WriteString(fmt.Sprintf("        chars: %d\n", k.Rotation.Generator.Chars))
				}
			}
		}

		if k.Expiry != nil {
			sb.WriteString("    expiry:\n")
			sb.WriteString(fmt.Sprintf("      expiresAt: \"%s\"\n", k.Expiry.ExpiresAt))
			if k.Expiry.Source != "" {
				sb.WriteString(fmt.Sprintf("      source: %s\n", k.Expiry.Source))
			}
		}

		if k.OperatorHints != nil && k.OperatorHints.GSM != nil {
			sb.WriteString("    operatorHints:\n")
			sb.WriteString("      gsm:\n")
			sb.WriteString(fmt.Sprintf("        secretResource: %s\n", k.OperatorHints.GSM.SecretResource))
			sb.WriteString(fmt.Sprintf("        version: \"%s\"\n", k.OperatorHints.GSM.Version))
			if k.OperatorHints.Format != "" {
				sb.WriteString(fmt.Sprintf("      format: %s\n", k.OperatorHints.Format))
			}
		}

		if k.Computed != nil {
			sb.WriteString("    computed:\n")
			sb.WriteString(fmt.Sprintf("      kind: %s\n", k.Computed.Kind))
			sb.WriteString(fmt.Sprintf("      template: %q\n", k.Computed.Template))
			if len(k.Computed.Inputs) > 0 {
				sb.WriteString("      inputs:\n")
				for _, input := range k.Computed.Inputs {
					sb.WriteString(fmt.Sprintf("        - var: %s\n", input.Var))
					sb.WriteString("          ref:\n")
					sb.WriteString(fmt.Sprintf("            keyName: %s\n", input.Ref.KeyName))
				}
			}
			if len(k.Computed.Params) > 0 {
				sb.WriteString("      params:\n")
				for pk, pv := range k.Computed.Params {
					sb.WriteString(fmt.Sprintf("        %s: %q\n", pk, pv))
				}
			}
		}
	}

	return sb.String()
}
