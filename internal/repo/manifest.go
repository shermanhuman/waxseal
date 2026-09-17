package repo

import (
	"fmt"
	"os"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
)

// ManifestPath returns the absolute path of a secret's SealedSecret manifest.
func (r *Repo) ManifestPath(m *core.SecretMetadata) (string, error) {
	return r.resolve("manifestPath", m.ManifestPath)
}

// Manifest loads a secret's SealedSecret manifest. It returns an error
// wrapping core.ErrNotFound when the manifest does not exist yet.
func (r *Repo) Manifest(m *core.SecretMetadata) (*seal.SealedSecret, error) {
	path, err := r.ManifestPath(m)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound("manifest "+m.ManifestPath, err)
		}
		return nil, fmt.Errorf("read manifest %s: %w", m.ManifestPath, err)
	}
	ss, err := seal.ParseSealedSecret(data)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", m.ManifestPath, err)
	}
	return ss, nil
}

// Commit writes a secret's metadata and manifest together.
//
// Both files are fully staged before either is put in place, so a validation
// or disk error changes nothing. Metadata is put in place first: it holds the
// pointer to the GSM version, which cannot be recovered from anywhere else,
// whereas a stale manifest is repaired by resealing.
func (r *Repo) Commit(m *core.SecretMetadata, ss *seal.SealedSecret) error {
	manifestPath, err := r.ManifestPath(m)
	if err != nil {
		return err
	}
	if ss.Metadata.Name != m.SealedSecret.Name || ss.Metadata.Namespace != m.SealedSecret.Namespace {
		return core.NewValidationError("manifest", fmt.Sprintf(
			"manifest is for %s/%s but metadata says %s/%s",
			ss.Metadata.Namespace, ss.Metadata.Name, m.SealedSecret.Namespace, m.SealedSecret.Name))
	}
	content, err := ss.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}

	meta, err := r.stageMetadata(m)
	if err != nil {
		return err
	}
	manifest, err := stage(manifestPath, content, func(b []byte) error {
		_, err := seal.ParseSealedSecret(b)
		return err
	})
	if err != nil {
		meta.discard()
		return err
	}

	if err := meta.commit(); err != nil {
		manifest.discard()
		return err
	}
	return manifest.commit()
}

// DeleteManifest removes a secret's manifest. A manifest that is already gone
// is not an error.
func (r *Repo) DeleteManifest(m *core.SecretMetadata) error {
	path, err := r.ManifestPath(m)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete manifest %s: %w", m.ManifestPath, err)
	}
	return nil
}
