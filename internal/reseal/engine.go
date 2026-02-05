// Package reseal implements the reseal orchestration logic.
package reseal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/logging"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/template"
)

// Engine performs reseal operations.
type Engine struct {
	store   store.Store
	sealer  seal.Sealer
	repoDir string
	dryRun  bool
}

// NewEngine creates a new reseal engine.
func NewEngine(store store.Store, sealer seal.Sealer, repoDir string, dryRun bool) *Engine {
	return &Engine{
		store:   store,
		sealer:  sealer,
		repoDir: repoDir,
		dryRun:  dryRun,
	}
}

// Result represents the result of a reseal operation.
type Result struct {
	ShortName    string
	KeysResealed int
	Error        error
	DryRun       bool
}

// ResealOne reseals a single secret by its short name.
func (e *Engine) ResealOne(ctx context.Context, shortName string) (*Result, error) {
	// Load metadata
	metadataPath := filepath.Join(e.repoDir, ".waxseal", "metadata", shortName+".yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(shortName, err)
		}
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	metadata, err := core.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}

	// Check if retired
	if metadata.IsRetired() {
		return nil, fmt.Errorf("%s: %w", shortName, core.ErrRetired)
	}

	return e.resealFromMetadata(ctx, metadata)
}

// ResealAll reseals all active secrets.
func (e *Engine) ResealAll(ctx context.Context) ([]*Result, error) {
	metadataDir := filepath.Join(e.repoDir, ".waxseal", "metadata")
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(metadataDir, err)
		}
		return nil, fmt.Errorf("read metadata directory: %w", err)
	}

	var results []*Result
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		shortName := strings.TrimSuffix(entry.Name(), ".yaml")

		// Check if retired before attempting reseal
		metadataPath := filepath.Join(metadataDir, entry.Name())
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			results = append(results, &Result{
				ShortName: shortName,
				Error:     err,
			})
			continue
		}
		metadata, err := core.ParseMetadata(data)
		if err != nil {
			results = append(results, &Result{
				ShortName: shortName,
				Error:     err,
			})
			continue
		}

		// Skip retired secrets silently
		if metadata.IsRetired() {
			logging.Info("skipping retired secret", "shortName", shortName)
			continue
		}

		result, err := e.resealFromMetadata(ctx, metadata)
		if err != nil {
			// Record error but continue with other secrets
			results = append(results, &Result{
				ShortName: shortName,
				Error:     err,
			})
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func (e *Engine) resealFromMetadata(ctx context.Context, metadata *core.SecretMetadata) (*Result, error) {
	logging.Info("resealing secret",
		"shortName", metadata.ShortName,
		"keyCount", len(metadata.Keys),
	)

	// Fetch all GSM values first
	keyValues := make(map[string]string)
	for _, key := range metadata.Keys {
		if key.Source.Kind == "gsm" && key.GSM != nil {
			value, err := e.store.AccessVersion(ctx, key.GSM.SecretResource, key.GSM.Version)
			if err != nil {
				return nil, fmt.Errorf("fetch %s/%s: %w", metadata.ShortName, key.KeyName, err)
			}
			keyValues[key.KeyName] = string(value)
			logging.Debug("fetched key from GSM",
				"key", key.KeyName,
				"version", key.GSM.Version,
			)
		}
	}

	// Evaluate computed keys
	for _, key := range metadata.Keys {
		if key.Source.Kind == "computed" && key.Computed != nil {
			// Check if we have a GSM-backed JSON payload
			if key.Computed.GSM != nil {
				// Fetch the JSON payload from GSM
				payloadData, err := e.store.AccessVersion(ctx, key.Computed.GSM.SecretResource, key.Computed.GSM.Version)
				if err != nil {
					return nil, fmt.Errorf("fetch computed payload %s/%s: %w", metadata.ShortName, key.KeyName, err)
				}
				// Parse as a Payload and get the computed value
				payload, err := template.ParsePayload(payloadData)
				if err != nil {
					return nil, fmt.Errorf("parse computed payload %s/%s: %w", metadata.ShortName, key.KeyName, err)
				}
				computed, err := payload.Compute()
				if err != nil {
					return nil, fmt.Errorf("render computed payload %s/%s: %w", metadata.ShortName, key.KeyName, err)
				}
				keyValues[key.KeyName] = computed
				logging.Debug("fetched computed key from GSM", "key", key.KeyName, "version", key.Computed.GSM.Version)
			} else {
				// Fallback: evaluate template using other keys as inputs
				// First, validate that templates with variables have a way to resolve them
				if key.Computed.Kind == "template" && key.Computed.Template != "" {
					// Check if the template has variables that need resolving
					hasVariables := strings.Contains(key.Computed.Template, "{{")
					hasInputs := len(key.Computed.Inputs) > 0
					hasParams := len(key.Computed.Params) > 0

					if hasVariables && !hasInputs && !hasParams {
						// Template has variables but no inputs or params - this is a configuration error
						// The user likely needs to add computed.gsm to point to a JSON payload
						return nil, fmt.Errorf(
							"computed key %s/%s: template has variables but no GSM reference, inputs, or params configured.\n"+
								"For templated database URLs, add a 'gsm' section under 'computed' pointing to the JSON payload in GSM.\n"+
								"Example:\n"+
								"  computed:\n"+
								"    kind: template\n"+
								"    template: \"...\"\n"+
								"    gsm:\n"+
								"      secretResource: projects/PROJECT/secrets/SECRET_NAME\n"+
								"      version: \"1\"",
							metadata.ShortName, key.KeyName,
						)
					}
				}
				value, err := e.evaluateComputed(key.Computed, keyValues, metadata.Keys)
				if err != nil {
					return nil, fmt.Errorf("compute %s/%s: %w", metadata.ShortName, key.KeyName, err)
				}
				keyValues[key.KeyName] = value
				logging.Debug("computed key", "key", key.KeyName)
			}
		}
	}

	// Seal all keys
	encryptedData := make(map[string]string)
	scope := metadata.SealedSecret.Scope
	name := metadata.SealedSecret.Name
	namespace := metadata.SealedSecret.Namespace

	for keyName, plaintext := range keyValues {
		encrypted, err := e.sealer.Seal(name, namespace, keyName, []byte(plaintext), scope)
		if err != nil {
			return nil, fmt.Errorf("seal %s/%s: %w", metadata.ShortName, keyName, err)
		}
		encryptedData[keyName] = encrypted
	}

	// Build the SealedSecret manifest
	manifest := e.buildManifest(metadata, encryptedData)

	// Write the manifest
	manifestPath := metadata.ManifestPath
	if !filepath.IsAbs(manifestPath) {
		manifestPath = filepath.Join(e.repoDir, manifestPath)
	}

	if e.dryRun {
		logging.Info("dry run - would write manifest",
			"path", manifestPath,
			"keys", len(encryptedData),
		)
		return &Result{
			ShortName:    metadata.ShortName,
			KeysResealed: len(encryptedData),
			DryRun:       true,
		}, nil
	}

	writer := files.NewAtomicWriter(files.YAMLKindValidator("SealedSecret"))
	if err := writer.Write(manifestPath, []byte(manifest)); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}

	logging.Info("wrote sealed manifest",
		"path", manifestPath,
		"keys", len(encryptedData),
	)

	return &Result{
		ShortName:    metadata.ShortName,
		KeysResealed: len(encryptedData),
	}, nil
}

func (e *Engine) evaluateComputed(config *core.ComputedConfig, keyValues map[string]string, allKeys []core.KeyMetadata) (string, error) {
	if config.Kind != "template" {
		return "", core.NewValidationError("computed.kind", "only 'template' is supported")
	}

	// Parse template
	tmpl, err := template.Parse(config.Template)
	if err != nil {
		return "", err
	}

	// Build resolver
	resolver := template.NewResolver()

	// Add GSM key values
	for k, v := range keyValues {
		resolver.SetKeyValue(k, v)
	}

	// Add static params
	if config.Params != nil {
		resolver.SetParams(config.Params)
	}

	// Resolve inputs
	var inputs []template.InputRef
	for _, input := range config.Inputs {
		inputs = append(inputs, template.InputRef{
			Var:       input.Var,
			ShortName: input.Ref.ShortName,
			KeyName:   input.Ref.KeyName,
		})
	}

	values, err := resolver.ResolveInputs(inputs)
	if err != nil {
		return "", err
	}

	// Execute template
	return tmpl.Execute(values)
}

func (e *Engine) buildManifest(metadata *core.SecretMetadata, encryptedData map[string]string) string {
	var sb strings.Builder

	sb.WriteString("apiVersion: bitnami.com/v1alpha1\n")
	sb.WriteString("kind: SealedSecret\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", metadata.SealedSecret.Name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", metadata.SealedSecret.Namespace))

	// Add scope annotation if not strict (using controller's annotation format)
	if metadata.SealedSecret.Scope == "namespace-wide" {
		sb.WriteString("  annotations:\n")
		sb.WriteString("    sealedsecrets.bitnami.com/namespace-wide: \"true\"\n")
	} else if metadata.SealedSecret.Scope == "cluster-wide" {
		sb.WriteString("  annotations:\n")
		sb.WriteString("    sealedsecrets.bitnami.com/cluster-wide: \"true\"\n")
	}

	sb.WriteString("spec:\n")
	sb.WriteString("  encryptedData:\n")

	// Sort keys for deterministic output
	keys := make([]string, 0, len(encryptedData))
	for k := range encryptedData {
		keys = append(keys, k)
	}
	sortStrings(keys)

	for _, key := range keys {
		sb.WriteString(fmt.Sprintf("    %s: %s\n", key, encryptedData[key]))
	}

	// Add template if there's a specific type
	if metadata.SealedSecret.Type != "" && metadata.SealedSecret.Type != "Opaque" {
		sb.WriteString("  template:\n")
		sb.WriteString(fmt.Sprintf("    type: %s\n", metadata.SealedSecret.Type))
		sb.WriteString("    metadata:\n")
		sb.WriteString(fmt.Sprintf("      name: %s\n", metadata.SealedSecret.Name))
		sb.WriteString(fmt.Sprintf("      namespace: %s\n", metadata.SealedSecret.Namespace))
	}

	return sb.String()
}

// Simple string sort without importing sort package
func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
