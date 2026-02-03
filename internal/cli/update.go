package cli

import (
	"bufio"
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

var updateCmd = &cobra.Command{
	Use:   "update <shortName> <keyName>",
	Short: "Update a secret key's value",
	Long: `Update a secret key's value in GSM and reseal the SealedSecret.

This command:
  1. Creates a new version in GSM with the new value
  2. Updates the metadata with the new version number
  3. Reseals the SealedSecret manifest

Examples:
  # Interactive mode (prompts for new value)
  waxseal update my-app-secrets api_key

  # Generate new random value
  waxseal update my-app-secrets api_key --generate-random

  # From stdin
  echo "new-value" | waxseal update my-app-secrets api_key --stdin

  # Preview changes
  waxseal update my-app-secrets api_key --generate-random --dry-run`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdate,
}

var (
	updateFromStdin      bool
	updateGenerateRandom bool
	updateRandomLength   int
)

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&updateFromStdin, "stdin", false, "Read new value from stdin")
	updateCmd.Flags().BoolVar(&updateGenerateRandom, "generate-random", false, "Generate a random value")
	updateCmd.Flags().IntVar(&updateRandomLength, "random-length", 32, "Length of generated random value (bytes)")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	shortName := args[0]
	keyName := args[1]

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
		return fmt.Errorf("cannot update retired secret %q", shortName)
	}

	// Find the key
	var keyIndex = -1
	for i, k := range metadata.Keys {
		if k.KeyName == keyName {
			keyIndex = i
			break
		}
	}
	if keyIndex == -1 {
		return fmt.Errorf("key %q not found in secret %q", keyName, shortName)
	}

	keyMeta := &metadata.Keys[keyIndex]
	if keyMeta.GSM == nil {
		return fmt.Errorf("key %q has no GSM reference", keyName)
	}

	// Load config
	cfgFile := configPath
	if !filepath.IsAbs(cfgFile) {
		cfgFile = filepath.Join(repoPath, cfgFile)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Get new value
	var newValue []byte
	if updateGenerateRandom {
		bytes := make([]byte, updateRandomLength)
		if _, err := rand.Read(bytes); err != nil {
			return fmt.Errorf("generate random bytes: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(bytes)
		newValue = []byte(encoded)
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
	fmt.Printf("Updating key: %s/%s\n", shortName, keyName)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("  GSM Resource: %s\n", keyMeta.GSM.SecretResource)
	fmt.Printf("  Old Version:  %s\n", keyMeta.GSM.Version)
	fmt.Println()

	if dryRun {
		fmt.Println("[DRY RUN] Would:")
		fmt.Println("  1. Create new version in GSM")
		fmt.Println("  2. Update metadata with new version")
		fmt.Println("  3. Reseal SealedSecret manifest")
		return nil
	}

	// Create new GSM version
	gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		return fmt.Errorf("create GSM store: %w", err)
	}
	defer gsmStore.Close()

	newVersion, err := gsmStore.CreateSecretVersion(ctx, keyMeta.GSM.SecretResource, newValue)
	if err != nil {
		return fmt.Errorf("create GSM version: %w", err)
	}
	fmt.Printf("✓ Created new GSM version: %s\n", newVersion)

	// Update metadata
	keyMeta.GSM.Version = newVersion
	metadataYAML := serializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(metadataYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	fmt.Printf("✓ Updated metadata: version %s\n", newVersion)

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

	// Load cert and sealer
	certPath := filepath.Join(repoPath, cfg.Cert.RepoCertPath)
	sealer, err := seal.NewCertSealerFromFile(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

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
	fmt.Printf("✓ Updated manifest: %s\n", metadata.ManifestPath)

	fmt.Println()
	fmt.Printf("✓ Key %s/%s updated successfully!\n", shortName, keyName)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Commit the updated files")
	fmt.Println("  2. Apply to cluster or let GitOps sync")

	return nil
}
