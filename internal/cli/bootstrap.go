package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap <shortName>",
	Short: "Push cluster secrets to GSM",
	Long: `Read a Secret from your Kubernetes cluster and push its values to GSM.

This establishes GSM as the source of truth for existing secrets.
After bootstrap, you can manage the secret entirely through waxseal.

Prerequisites:
  - kubectl configured with cluster access
  - GSM API enabled and IAM permissions to create secrets
  - SealedSecret already discovered (run 'waxseal discover' first)

Examples:
  # Bootstrap a discovered secret
  waxseal bootstrap my-app-secrets

  # Preview what would be pushed
  waxseal bootstrap my-app-secrets --dry-run

  # Specify kubeconfig
  waxseal bootstrap my-app-secrets --kubeconfig ~/.kube/config

Exit codes:
  0 - Success
  1 - Failed to read from cluster or push to GSM`,
	Args: cobra.ExactArgs(1),
	RunE: runBootstrap,
}

var bootstrapKubeconfig string

func init() {
	rootCmd.AddCommand(bootstrapCmd)
	bootstrapCmd.Flags().StringVar(&bootstrapKubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
}

func runBootstrap(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	shortName := args[0]

	// Load metadata
	metadataPath := filepath.Join(repoPath, ".waxseal", "metadata", shortName+".yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("secret %q not found. Run 'waxseal discover' first", shortName)
		}
		return fmt.Errorf("read metadata: %w", err)
	}

	metadata, err := core.ParseMetadata(data)
	if err != nil {
		return fmt.Errorf("parse metadata: %w", err)
	}

	if metadata.IsRetired() {
		return fmt.Errorf("secret %q is retired", shortName)
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

	// Read secret from cluster
	secretData, err := readSecretFromCluster(ctx, metadata.SealedSecret.Namespace, metadata.SealedSecret.Name)
	if err != nil {
		return fmt.Errorf("read secret from cluster: %w", err)
	}

	fmt.Printf("Found secret %s/%s with %d keys\n",
		metadata.SealedSecret.Namespace,
		metadata.SealedSecret.Name,
		len(secretData))

	// Track which keys to push
	type keyToPush struct {
		keyName        string
		value          []byte
		gsmResource    string
		existingConfig *core.KeyMetadata
	}

	var keysToPush []keyToPush

	for keyName, value := range secretData {
		// Find existing key config or create new
		var existing *core.KeyMetadata
		for i := range metadata.Keys {
			if metadata.Keys[i].KeyName == keyName {
				existing = &metadata.Keys[i]
				break
			}
		}

		// Generate GSM resource name
		gsmResource := fmt.Sprintf("projects/%s/secrets/%s-%s",
			cfg.Store.ProjectID,
			shortName,
			sanitizeGSMName(keyName))

		keysToPush = append(keysToPush, keyToPush{
			keyName:        keyName,
			value:          value,
			gsmResource:    gsmResource,
			existingConfig: existing,
		})

		fmt.Printf("  %s → %s\n", keyName, gsmResource)
	}

	if dryRun {
		fmt.Println("\n[DRY RUN] Would push secrets to GSM and update metadata")
		return nil
	}

	if !yes {
		fmt.Print("\nPush these secrets to GSM? [y/N]: ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Create GSM store
	gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		return fmt.Errorf("create GSM store: %w", err)
	}
	defer gsmStore.Close()

	// Push each key to GSM
	for _, k := range keysToPush {
		version, err := gsmStore.CreateSecretVersion(ctx, k.gsmResource, k.value)
		if err != nil {
			return fmt.Errorf("push %s to GSM: %w", k.keyName, err)
		}
		fmt.Printf("✓ Pushed %s (version %s)\n", k.keyName, version)

		// Update metadata
		found := false
		for i := range metadata.Keys {
			if metadata.Keys[i].KeyName == k.keyName {
				metadata.Keys[i].GSM = &core.GSMRef{
					SecretResource: k.gsmResource,
					Version:        version,
				}
				if metadata.Keys[i].Source.Kind == "" {
					metadata.Keys[i].Source.Kind = "gsm"
				}
				found = true
				break
			}
		}

		if !found {
			// Add new key to metadata
			metadata.Keys = append(metadata.Keys, core.KeyMetadata{
				KeyName: k.keyName,
				Source:  core.SourceConfig{Kind: "gsm"},
				GSM: &core.GSMRef{
					SecretResource: k.gsmResource,
					Version:        version,
				},
				Rotation: &core.RotationConfig{Mode: "manual"},
			})
		}
	}

	// Write updated metadata
	updatedYAML := serializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(updatedYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	fmt.Printf("\n✓ Bootstrap complete for %s\n", shortName)
	fmt.Println("\nNext steps:")
	fmt.Printf("  1. Run 'waxseal reseal %s' to refresh the SealedSecret\n", shortName)
	fmt.Println("  2. Commit the updated metadata")

	return nil
}

// readSecretFromCluster uses kubectl to read a secret from the cluster.
// This is a variable to allow test injection.
var readSecretFromCluster = defaultReadSecretFromCluster

func defaultReadSecretFromCluster(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	// Build kubectl command
	args := []string{"get", "secret", name, "-n", namespace, "-o", "yaml"}

	if bootstrapKubeconfig != "" {
		args = append([]string{"--kubeconfig", bootstrapKubeconfig}, args...)
	}

	// Execute kubectl
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("kubectl failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("kubectl get secret: %w", err)
	}

	// Parse YAML
	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(output, &secret); err != nil {
		return nil, fmt.Errorf("parse secret YAML: %w", err)
	}

	// Decode base64 values
	result := make(map[string][]byte)
	for key, encoded := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", key, err)
		}
		result[key] = decoded
	}

	return result, nil
}

// sanitizeGSMName converts a key name to a valid GSM secret name component.
func sanitizeGSMName(name string) string {
	// GSM allows: letters, numbers, hyphens, underscores
	// Replace dots and other chars with hyphens
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)

	// Remove leading/trailing hyphens
	return strings.Trim(result, "-")
}
