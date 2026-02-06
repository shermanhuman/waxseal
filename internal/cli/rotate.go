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
	"github.com/shermanhuman/waxseal/internal/state"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
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

For keys with rotation.mode=external:
  - Displays operator hints if available
  - Waits for confirmation that the value has been updated externally
  - Updates metadata with new version number
  - Reseals the manifest

For keys with rotation.mode=static:
  - Only rotated when explicitly specified by keyName (skipped in batch operations)
  - Prompts for the new value
  - Adds a new version to GSM
  - Reseals the manifest

Examples:
  # Rotate a specific key
  waxseal rotate my-app-secrets password

  # Rotate all generated keys in a secret
  waxseal rotate my-app-secrets --generated

  # Manually update a static key (e.g., one-time password change)
  waxseal rotate my-app-secrets admin_password

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
		// Include both GSM keys AND computed keys with generated rotation
		if k.Source.Kind != "gsm" && k.Source.Kind != "computed" {
			continue
		}

		// For computed keys, must have generated rotation mode
		if k.Source.Kind == "computed" {
			if k.Rotation == nil || k.Rotation.Mode != "generated" {
				continue
			}
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
	for _, key := range keysToRotate {
		fmt.Printf("\nRotating %s/%s...\n", shortName, key.KeyName)

		if key.Rotation == nil {
			fmt.Printf("  Skipping: no rotation config\n")
			continue
		}

		var newValue []byte
		var err error

		switch key.Rotation.Mode {
		case "generated":
			// For computed keys, we need to handle JSON payloads
			if key.Source.Kind == "computed" {
				// Get GSM resource from computed config
				gsmResource := ""
				if key.Computed != nil && key.Computed.GSM != nil {
					gsmResource = key.Computed.GSM.SecretResource
				}
				if gsmResource == "" {
					fmt.Printf("  Skipping: no GSM resource for computed key\n")
					continue
				}

				// Read existing payload from GSM
				existingData, err := secretStore.AccessVersion(ctx, gsmResource, "latest")
				if err != nil {
					return fmt.Errorf("read existing payload for %s: %w", key.KeyName, err)
				}

				payload, err := template.ParsePayload(existingData)
				if err != nil {
					return fmt.Errorf("parse payload for %s: %w", key.KeyName, err)
				}

				// Generate new secret value
				secretBytes, err := generateValue(key.Rotation.Generator)
				if err != nil {
					return fmt.Errorf("generate value for %s: %w", key.KeyName, err)
				}
				newSecret := string(secretBytes)

				// Update payload with new secret
				if err := payload.UpdateSecret(newSecret); err != nil {
					return fmt.Errorf("update payload for %s: %w", key.KeyName, err)
				}
				fmt.Printf("  Generated new secret (%d chars)\n", len(newSecret))
				fmt.Printf("  Recomputed: %s...\n", truncateStr(payload.Computed, 50))

				// Marshal and store as newValue
				newValue, err = payload.Marshal()
				if err != nil {
					return fmt.Errorf("marshal payload for %s: %w", key.KeyName, err)
				}

				if !dryRun {
					newVersion, err := secretStore.AddVersion(ctx, gsmResource, newValue)
					if err != nil {
						return fmt.Errorf("add GSM version for %s: %w", key.KeyName, err)
					}
					fmt.Printf("  Added GSM version: %s\n", newVersion)

					// Find and update metadata
					for j := range metadata.Keys {
						if metadata.Keys[j].KeyName == key.KeyName {
							if metadata.Keys[j].Computed != nil && metadata.Keys[j].Computed.GSM != nil {
								metadata.Keys[j].Computed.GSM.Version = newVersion
							}
							break
						}
					}
					metadataUpdated = true
				} else {
					fmt.Printf("  [DRY RUN] Would add new version to GSM\n")
				}
				continue
			}

			// Regular GSM key generation
			newValue, err = generateValue(key.Rotation.Generator)
			if err != nil {
				return fmt.Errorf("generate value for %s: %w", key.KeyName, err)
			}
			fmt.Printf("  Generated new value (%d bytes)\n", len(newValue))

		case "external":
			fmt.Printf("  Mode: %s\n", key.Rotation.Mode)
			if key.OperatorHints != nil {
				displayOperatorHints(key.OperatorHints, key.KeyName)
			}

			// For computed keys with external rotation, prompt for the new secret value
			if key.Source.Kind == "computed" {
				gsmResource := ""
				if key.Computed != nil && key.Computed.GSM != nil {
					gsmResource = key.Computed.GSM.SecretResource
				}
				if gsmResource == "" {
					fmt.Printf("  Skipping: no GSM resource for computed key\n")
					continue
				}

				// Read existing payload
				existingData, err := secretStore.AccessVersion(ctx, gsmResource, "latest")
				if err != nil {
					return fmt.Errorf("read existing payload for %s: %w", key.KeyName, err)
				}

				payload, err := template.ParsePayload(existingData)
				if err != nil {
					return fmt.Errorf("parse payload for %s: %w", key.KeyName, err)
				}

				// Prompt for new secret value (masked input)
				fmt.Println("  After updating externally, enter the new secret value:")
				var newSecret string
				if !dryRun && !yes {
					var err error
					newSecret, err = promptSecret("New {{secret}}")
					if err != nil {
						return fmt.Errorf("prompt for secret: %w", err)
					}
				}

				if newSecret == "" {
					fmt.Println("  Skipping: no new value entered")
					continue
				}

				// Update payload with new secret
				if err := payload.UpdateSecret(newSecret); err != nil {
					return fmt.Errorf("update payload for %s: %w", key.KeyName, err)
				}
				fmt.Printf("  Updated secret value\n")
				fmt.Printf("  Recomputed: %s...\n", truncateStr(payload.Computed, 50))

				// Store new version
				newValue, err = payload.Marshal()
				if err != nil {
					return fmt.Errorf("marshal payload for %s: %w", key.KeyName, err)
				}

				if !dryRun {
					newVersion, err := secretStore.AddVersion(ctx, gsmResource, newValue)
					if err != nil {
						return fmt.Errorf("add GSM version for %s: %w", key.KeyName, err)
					}
					fmt.Printf("  Added GSM version: %s\n", newVersion)

					// Update metadata
					for j := range metadata.Keys {
						if metadata.Keys[j].KeyName == key.KeyName {
							if metadata.Keys[j].Computed != nil && metadata.Keys[j].Computed.GSM != nil {
								metadata.Keys[j].Computed.GSM.Version = newVersion
							}
							break
						}
					}
					metadataUpdated = true
				} else {
					fmt.Printf("  [DRY RUN] Would add new version to GSM\n")
				}
				continue
			}

			// Regular GSM key - just wait for user to update externally
			if !dryRun && !yes {
				ok, err := confirm("Have you updated the value externally?")
				if err != nil {
					return fmt.Errorf("confirmation: %w", err)
				}
				if !ok {
					fmt.Println("  Skipping")
					continue
				}
			}
			// For external/manual non-templated, we don't generate - we expect GSM to have been updated
			// Just increment version reference
			continue

		case "static":
			// Static mode: only allow when explicitly specified by keyName,
			// skip in batch operations (--generated flag)
			if keyName == "" {
				fmt.Printf("  Skipping: static mode keys are not included in batch rotation\n")
				continue
			}

			fmt.Printf("  Mode: static (manual update requested)\n")
			if key.OperatorHints != nil {
				displayOperatorHints(key.OperatorHints, key.KeyName)
			}

			// Prompt for new value (masked input)
			fmt.Println("  Enter the new value for this static secret:")
			var inputValue string
			if !dryRun && !yes {
				var err error
				inputValue, err = promptSecret("New value")
				if err != nil {
					return fmt.Errorf("prompt for value: %w", err)
				}
			}

			if inputValue == "" {
				fmt.Println("  Skipping: no new value entered")
				continue
			}

			newValue = []byte(inputValue)
			fmt.Printf("  New value set (%d characters)\n", len(inputValue))

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

		// Add new version to GSM (for regular GSM keys)
		newVersion, err := secretStore.AddVersion(ctx, key.GSM.SecretResource, newValue)
		if err != nil {
			return fmt.Errorf("add GSM version for %s: %w", key.KeyName, err)
		}
		fmt.Printf("  Added GSM version: %s\n", newVersion)

		// Update metadata with new version
		for j := range metadata.Keys {
			if metadata.Keys[j].KeyName == key.KeyName {
				metadata.Keys[j].GSM.Version = newVersion
				break
			}
		}
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
		fmt.Printf("\n")
		printSuccess("Updated metadata: %s", metadataPath)
	}

	// Reseal
	fmt.Println("\nResealing...")

	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}
	// Use kubeseal binary for encryption (guarantees controller compatibility)
	sealer := seal.NewKubesealSealer(certPath)

	engine := reseal.NewEngine(secretStore, sealer, repoPath, dryRun)
	result, err := engine.ResealOne(ctx, shortName)
	if err != nil {
		return fmt.Errorf("reseal: %w", err)
	}

	if result.DryRun {
		printSuccess("Would reseal %d keys [DRY RUN]", result.KeysResealed)
	} else {
		printSuccess("Resealed %d keys", result.KeysResealed)
		// Record rotation in state
		if err := recordRotateState(shortName, keyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update state: %v\n", err)
		}
	}

	return nil
}

// recordRotateState adds a rotation record to state.yaml.
func recordRotateState(shortName, keyName string) error {
	s, err := state.Load(repoPath)
	if err != nil {
		return err
	}
	s.AddRotation(shortName, keyName, "rotate", "")
	return s.Save(repoPath)
}

func generateValue(gen *core.GeneratorConfig) ([]byte, error) {
	if gen == nil {
		return nil, fmt.Errorf("no generator config")
	}

	byteCount := gen.Bytes
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

// truncateStr shortens a string to maxLen characters, adding "..." if truncated.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
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
			}
		}

		if k.Expiry != nil {
			sb.WriteString("    expiry:\n")
			sb.WriteString(fmt.Sprintf("      expiresAt: \"%s\"\n", k.Expiry.ExpiresAt))
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
