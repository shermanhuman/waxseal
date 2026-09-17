package repo

import (
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/config"
)

// ConfigPath returns the absolute path of the waxseal config file.
func (r *Repo) ConfigPath() string {
	return filepath.Join(r.root, ".waxseal", "config.yaml")
}

// Config loads the config with defaults applied. It returns an error wrapping
// core.ErrNotFound when the repository has not been initialised.
func (r *Repo) Config() (*config.Config, error) {
	return config.Load(r.ConfigPath())
}

// WriteConfig validates and atomically writes the config.
func (r *Repo) WriteConfig(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	content, err := cfg.Marshal()
	if err != nil {
		return err
	}
	return write(r.ConfigPath(), content, func(b []byte) error {
		_, err := config.Parse(b)
		return err
	})
}
