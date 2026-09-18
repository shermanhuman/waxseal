package repo

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/seal"
)

// Found is a SealedSecret manifest located in the repository.
type Found struct {
	// Path is repo-relative with forward slashes, as stored in metadata.
	Path   string
	Secret *seal.SealedSecret
}

// FindManifests walks the repository for SealedSecret manifests, skipping
// dot-directories. Files that are not SealedSecrets are ignored.
func (r *Repo) FindManifests() ([]Found, error) {
	var found []Found
	err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != r.root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(d.Name()); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		ss, err := seal.ParseSealedSecret(data)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(r.root, path)
		if err != nil {
			return err
		}
		found = append(found, Found{Path: filepath.ToSlash(rel), Secret: ss})
		return nil
	})
	return found, err
}
