package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
)

// MetadataDir returns the absolute path to the metadata directory within a repo.
func MetadataDir(repoPath string) string {
	return filepath.Join(repoPath, ".waxseal", "metadata")
}

// MetadataPath returns the absolute path to a metadata file for a given shortName.
func MetadataPath(repoPath, shortName string) string {
	return filepath.Join(MetadataDir(repoPath), shortName+".yaml")
}

// LoadMetadata loads and parses a single metadata file by shortName.
// Returns core.ErrNotFound (wrapped) if the file does not exist.
func LoadMetadata(repoPath, shortName string) (*core.SecretMetadata, error) {
	path := MetadataPath(repoPath, shortName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(shortName, err)
		}
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	m, err := core.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("parse metadata %s: %w", shortName, err)
	}
	return m, nil
}

// MetadataExists returns true if a metadata file exists for the given shortName.
func MetadataExists(repoPath, shortName string) bool {
	_, err := os.Stat(MetadataPath(repoPath, shortName))
	return err == nil
}

// LoadAllMetadata loads and parses all metadata files from the repo.
// Returns core.ErrNotFound (wrapped) if the metadata directory does not exist.
// Files that fail to read or parse cause an immediate error return.
func LoadAllMetadata(repoPath string) ([]*core.SecretMetadata, error) {
	dir := MetadataDir(repoPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(dir, err)
		}
		return nil, fmt.Errorf("read metadata directory: %w", err)
	}

	var secrets []*core.SecretMetadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		m, err := core.ParseMetadata(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}

		secrets = append(secrets, m)
	}
	return secrets, nil
}

// LoadAllMetadataCollectErrors loads all metadata files, collecting errors
// instead of failing fast. Returns all successfully parsed metadata and a
// slice of per-file errors. The metadata directory not existing is still
// returned as a single error.
func LoadAllMetadataCollectErrors(repoPath string) (secrets []*core.SecretMetadata, errs []error) {
	dir := MetadataDir(repoPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("read metadata directory: %w", err)}
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", path, err))
			continue
		}

		m, err := core.ParseMetadata(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", entry.Name(), err))
			continue
		}

		secrets = append(secrets, m)
	}
	return secrets, errs
}

// ListMetadataNames returns the shortNames of all metadata files in the repo
// without parsing them. Useful for collecting names before delegating to
// per-secret operations.
func ListMetadataNames(repoPath string) ([]string, error) {
	dir := MetadataDir(repoPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(dir, err)
		}
		return nil, fmt.Errorf("read metadata directory: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".yaml"))
	}
	return names, nil
}

// SerializeMetadata converts a SecretMetadata struct to YAML string.
// This is the canonical serializer used by all CLI commands that write metadata.
func SerializeMetadata(m *core.SecretMetadata) string {
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
			if k.Computed.GSM != nil {
				sb.WriteString("      gsm:\n")
				sb.WriteString(fmt.Sprintf("        secretResource: %s\n", k.Computed.GSM.SecretResource))
				sb.WriteString(fmt.Sprintf("        version: \"%s\"\n", k.Computed.GSM.Version))
			}
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
