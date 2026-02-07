package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os/exec"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap [shortName]",
	Short: "Push cluster secrets to GSM",
	Long: `Read Secrets from your Kubernetes cluster and push their values to GSM.

This establishes GSM as the source of truth for existing secrets.
After bootstrap, you can manage the secrets entirely through waxseal.

If no shortName is provided, bootstraps ALL discovered secrets.

Prerequisites:
  - kubectl configured with cluster access
  - GSM API enabled and IAM permissions to create secrets
  - SealedSecrets already discovered (run 'waxseal discover' first)

Examples:
  # Bootstrap all discovered secrets
  waxseal bootstrap

  # Bootstrap a specific secret
  waxseal bootstrap my-app-secrets

  # Preview what would be pushed
  waxseal bootstrap --dry-run

  # Specify kubeconfig
  waxseal bootstrap --kubeconfig ~/.kube/config

Exit codes:
  0 - Success
  1 - Failed to read from cluster or push to GSM`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBootstrap,
}

var bootstrapKubeconfig string

func init() {
	// bootstrapCmd is added to gsmCmd in gcp_bootstrap.go
	bootstrapCmd.Flags().StringVar(&bootstrapKubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	addPreflightChecks(bootstrapCmd, authNeeds{gsm: true, kubectl: true})
}

func runBootstrap(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// If no arg provided, bootstrap all
	if len(args) == 0 {
		return bootstrapAll(ctx)
	}

	return bootstrapOne(ctx, args[0])
}

// bootstrapAll iterates over all discovered secrets and bootstraps each one.
func bootstrapAll(ctx context.Context) error {
	secrets, err := files.ListMetadataNames(repoPath)
	if err != nil {
		return fmt.Errorf("no secrets discovered. Run 'waxseal discover' first: %w", err)
	}

	if len(secrets) == 0 {
		return fmt.Errorf("no secrets found. Run 'waxseal discover' first")
	}

	fmt.Printf("Bootstrapping %d secrets...\n\n", len(secrets))

	successCount := 0
	for _, shortName := range secrets {
		fmt.Printf("Bootstrapping %s...\n", shortName)
		if err := bootstrapOne(ctx, shortName); err != nil {
			printWarning("%s: %v", shortName, err)
		} else {
			successCount++
		}
	}

	fmt.Println()
	printSuccess("Bootstrap complete: %d/%d secrets", successCount, len(secrets))
	return nil
}

// bootstrapOne bootstraps a single secret.
func bootstrapOne(ctx context.Context, shortName string) error {
	// Load metadata
	metadata, err := files.LoadMetadata(repoPath, shortName)
	if err != nil {
		return err
	}
	metadataPath := files.MetadataPath(repoPath, shortName)

	if metadata.IsRetired() {
		return fmt.Errorf("secret %q is retired", shortName)
	}

	// Load config
	cfg, err := resolveConfig()
	if err != nil {
		return err
	}

	// Read secret from cluster
	secretData, err := readSecretFromCluster(ctx, metadata.SealedSecret.Namespace, metadata.SealedSecret.Name)
	if err != nil {
		return fmt.Errorf("read secret from cluster: %w", err)
	}

	fmt.Printf("  Found %d keys in cluster\n", len(secretData))

	// Check for key mismatches between metadata and cluster
	clusterKeys := make(map[string]bool)
	for k := range secretData {
		clusterKeys[k] = true
	}

	var missingInCluster []string
	var extraInCluster []string

	for _, km := range metadata.Keys {
		if !clusterKeys[km.KeyName] {
			missingInCluster = append(missingInCluster, km.KeyName)
		}
	}

	metadataKeys := make(map[string]bool)
	for _, km := range metadata.Keys {
		metadataKeys[km.KeyName] = true
	}
	for k := range secretData {
		if !metadataKeys[k] {
			extraInCluster = append(extraInCluster, k)
		}
	}

	if len(missingInCluster) > 0 {
		printWarning("Keys in metadata but NOT in cluster: %v", missingInCluster)
		fmt.Println("     These keys will be skipped. Remove them from metadata or add to cluster.")
	}
	if len(extraInCluster) > 0 {
		fmt.Printf("  ℹ️  Keys in cluster but NOT in metadata: %v\n", extraInCluster)
		fmt.Println("     These will be added with default config.")
	}

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
		gsmResource := store.SecretResource(
			cfg.Store.ProjectID,
			store.FormatSecretID(shortName, keyName))

		keysToPush = append(keysToPush, keyToPush{
			keyName:        keyName,
			value:          value,
			gsmResource:    gsmResource,
			existingConfig: existing,
		})
	}

	if dryRun {
		fmt.Println("  [DRY RUN] Would push to GSM")
		return nil
	}

	// Create GSM store
	gsmStore, closeStore, err := resolveStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	// Push each key to GSM
	for _, k := range keysToPush {
		var dataToPush []byte
		isComputed := false

		// Check if this is a computed key (templated)
		if k.existingConfig != nil && k.existingConfig.Source.Kind == "computed" {
			isComputed = true
			// For computed keys, detect connection string and create JSON payload
			valueStr := string(k.value)
			allKeys := make([]string, 0, len(secretData))
			for kn := range secretData {
				allKeys = append(allKeys, kn)
			}

			// Detect template and extract values
			isTemplate, templateStr, extractedValues := template.DetectConnectionString(valueStr, allKeys)
			if isTemplate {
				// Get generator config if available
				var genConfig *template.GeneratorConfig
				if k.existingConfig.Rotation != nil && k.existingConfig.Rotation.Generator != nil {
					genConfig = &template.GeneratorConfig{
						Kind:  k.existingConfig.Rotation.Generator.Kind,
						Bytes: k.existingConfig.Rotation.Generator.Bytes,
					}
					if genConfig.Bytes == 0 {
						genConfig.Bytes = 32 // default
					}
				}

				// Extract the secret value (password from the connection string)
				secretValue := ""
				parsed, _ := url.Parse(valueStr)
				if parsed != nil && parsed.User != nil {
					if pw, ok := parsed.User.Password(); ok {
						secretValue = pw
					}
				}

				// Create the JSON payload
				payload, err := template.NewPayload(templateStr, extractedValues, secretValue, genConfig)
				if err != nil {
					return fmt.Errorf("create payload for %s: %w", k.keyName, err)
				}

				dataToPush, err = payload.Marshal()
				if err != nil {
					return fmt.Errorf("marshal payload for %s: %w", k.keyName, err)
				}
				fmt.Printf("  📦 %s: JSON payload\n", k.keyName)
			} else {
				// Computed but not a recognized template - push raw value
				dataToPush = k.value
			}
		} else {
			// Regular GSM key - push raw value
			dataToPush = k.value
		}

		version, err := gsmStore.CreateSecretVersion(ctx, k.gsmResource, dataToPush)
		if err != nil {
			return fmt.Errorf("push %s to GSM: %w", k.keyName, err)
		}
		fmt.Printf("  %s✓%s %s (v%s)\n", styleGreen, styleReset, k.keyName, version)

		// Update metadata
		found := false
		for i := range metadata.Keys {
			if metadata.Keys[i].KeyName == k.keyName {
				if isComputed {
					// For computed keys, update Computed.GSM instead of top-level GSM
					if metadata.Keys[i].Computed == nil {
						metadata.Keys[i].Computed = &core.ComputedConfig{}
					}
					metadata.Keys[i].Computed.GSM = &core.GSMRef{
						SecretResource: k.gsmResource,
						Version:        version,
					}
				} else {
					metadata.Keys[i].GSM = &core.GSMRef{
						SecretResource: k.gsmResource,
						Version:        version,
					}
				}
				if metadata.Keys[i].Source.Kind == "" {
					if isComputed {
						metadata.Keys[i].Source.Kind = "computed"
					} else {
						metadata.Keys[i].Source.Kind = "gsm"
					}
				}
				found = true
				break
			}
		}

		if !found {
			// Add new key to metadata
			sourceKind := "gsm"
			if isComputed {
				sourceKind = "computed"
			}
			newKey := core.KeyMetadata{
				KeyName:  k.keyName,
				Source:   core.SourceConfig{Kind: sourceKind},
				Rotation: &core.RotationConfig{Mode: "external"},
			}
			if isComputed {
				newKey.Computed = &core.ComputedConfig{
					GSM: &core.GSMRef{
						SecretResource: k.gsmResource,
						Version:        version,
					},
				}
			} else {
				newKey.GSM = &core.GSMRef{
					SecretResource: k.gsmResource,
					Version:        version,
				}
			}
			metadata.Keys = append(metadata.Keys, newKey)
		}
	}

	// Write updated metadata
	updatedYAML := serializeMetadata(metadata)
	writer := files.NewAtomicWriter()
	if err := writer.Write(metadataPath, []byte(updatedYAML)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

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
