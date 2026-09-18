// Package repo is the only code that reads or writes files under a waxseal
// repository. Every write is validated first and lands atomically, so a
// failure never leaves a half-written or unparseable file behind.
package repo

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Repo is a waxseal-managed repository rooted at a directory.
type Repo struct {
	root string
}

// Open returns the repository rooted at root.
func Open(root string) (*Repo, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(root, err)
		}
		return nil, fmt.Errorf("open repo: %w", err)
	}
	if !info.IsDir() {
		return nil, core.NewValidationError("repo", fmt.Sprintf("%s is not a directory", root))
	}
	return &Repo{root: abs}, nil
}

// Root returns the absolute path of the repository root.
func (r *Repo) Root() string { return r.root }

// resolve turns a repo-relative path into an absolute one, refusing anything
// that would land outside the repository.
func (r *Repo) resolve(field, rel string) (string, error) {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", core.NewValidationError(field, fmt.Sprintf("%q must be a relative path inside the repository", rel))
	}
	return filepath.Join(r.root, filepath.FromSlash(rel)), nil
}

// staged is a file written and synced to a temp name next to its target,
// waiting to be renamed into place.
type staged struct {
	tmp, target string
}

// stage validates content, then writes it to a temp file in the target's
// directory (rename is only atomic within a filesystem).
func stage(target string, content []byte, validate func([]byte) error) (*staged, error) {
	if len(content) == 0 {
		return nil, core.NewValidationError("content", "refusing to write an empty file")
	}
	if err := validate(content); err != nil {
		return nil, fmt.Errorf("refusing to write %s: %w", filepath.Base(target), err)
	}

	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".waxseal-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	s := &staged{tmp: tmp.Name(), target: target}

	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(s.tmp, 0o644)
	}
	if err != nil {
		s.discard()
		return nil, fmt.Errorf("write temp file for %s: %w", filepath.Base(target), err)
	}
	return s, nil
}

func (s *staged) commit() error {
	if err := os.Rename(s.tmp, s.target); err != nil {
		s.discard()
		return fmt.Errorf("replace %s: %w", s.target, err)
	}
	return nil
}

func (s *staged) discard() { _ = os.Remove(s.tmp) }

// write is the single path by which one file reaches the repository.
func write(target string, content []byte, validate func([]byte) error) error {
	s, err := stage(target, content, validate)
	if err != nil {
		return err
	}
	return s.commit()
}
