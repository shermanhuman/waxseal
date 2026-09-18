package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
)

const metadataExt = ".yaml"

func (r *Repo) metadataDir() string {
	return filepath.Join(r.root, ".waxseal", "metadata")
}

// MetadataPath returns the absolute path of a secret's metadata file.
func (r *Repo) MetadataPath(shortName string) string {
	return filepath.Join(r.metadataDir(), shortName+metadataExt)
}

// MetadataRel returns the repo-relative, slash-separated path of a secret's
// metadata file, for reporting.
func MetadataRel(shortName string) string {
	return ".waxseal/metadata/" + shortName + metadataExt
}

// Metadata loads one secret's metadata. It returns an error wrapping
// core.ErrNotFound when the secret is not registered.
func (r *Repo) Metadata(shortName string) (*core.SecretMetadata, error) {
	data, err := os.ReadFile(r.MetadataPath(shortName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound("secret "+shortName, err)
		}
		return nil, fmt.Errorf("read metadata for %s: %w", shortName, err)
	}
	m, err := core.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("metadata for %s: %w", shortName, err)
	}
	return m, nil
}

// AllMetadata loads every secret's metadata, ordered by file name. Files that
// fail to load are reported in errs and skipped, so one bad file does not hide
// the rest. A repository with no metadata directory has no secrets.
func (r *Repo) AllMetadata() (secrets []*core.SecretMetadata, errs []error) {
	entries, err := os.ReadDir(r.metadataDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read metadata directory: %w", err)}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), metadataExt) {
			continue
		}
		m, err := r.Metadata(strings.TrimSuffix(entry.Name(), metadataExt))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		secrets = append(secrets, m)
	}
	return secrets, errs
}

// WriteMetadata validates and atomically writes a secret's metadata.
func (r *Repo) WriteMetadata(m *core.SecretMetadata) error {
	s, err := r.stageMetadata(m)
	if err != nil {
		return err
	}
	return s.commit()
}

func (r *Repo) stageMetadata(m *core.SecretMetadata) (*staged, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	// The short name becomes a file name.
	if !filepath.IsLocal(m.ShortName) || strings.ContainsAny(m.ShortName, `/\`) {
		return nil, core.NewValidationError("shortName", fmt.Sprintf("%q is not usable as a file name", m.ShortName))
	}
	if _, err := r.resolve("manifestPath", m.ManifestPath); err != nil {
		return nil, err
	}
	content, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	// Re-parse the exact bytes: what is written must be what loads next time.
	return stage(r.MetadataPath(m.ShortName), content, func(b []byte) error {
		_, err := core.ParseMetadata(b)
		return err
	})
}
