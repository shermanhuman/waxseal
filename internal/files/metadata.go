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
