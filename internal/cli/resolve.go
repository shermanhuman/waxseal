package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/state"
	"github.com/shermanhuman/waxseal/internal/store"
)

// resolveConfig loads the waxseal config, resolving configPath relative to
// repoPath if necessary. This replaces ~11 copies of the same boilerplate.
func resolveConfig() (*config.Config, error) {
	cfgFile := configPath
	if !filepath.IsAbs(cfgFile) {
		cfgFile = filepath.Join(repoPath, cfgFile)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// resolveStore creates a secret store from config.
// Returns the store, a cleanup function (must be deferred), and any error.
func resolveStore(ctx context.Context, cfg *config.Config) (store.Store, func(), error) {
	if cfg.Store.Kind != "gsm" {
		return nil, nil, fmt.Errorf("unsupported store kind: %s", cfg.Store.Kind)
	}
	gsmStore, err := store.NewGSMStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		return nil, nil, fmt.Errorf("create GSM store: %w", err)
	}
	return gsmStore, func() { gsmStore.Close() }, nil
}

// resolveSealer creates a KubesealSealer from config, resolving the cert
// path relative to repoPath if necessary.
func resolveSealer(cfg *config.Config) *seal.KubesealSealer {
	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}
	return seal.NewKubesealSealer(certPath)
}

// resolveCertPath returns the absolute certificate path from config.
func resolveCertPath(cfg *config.Config) string {
	certPath := cfg.Cert.RepoCertPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(repoPath, certPath)
	}
	return certPath
}

// withState loads state, applies a mutation, and saves it back atomically.
// This replaces the repeated Load → mutate → Save pattern.
func withState(mutate func(*state.State)) error {
	s, err := state.Load(repoPath)
	if err != nil {
		return err
	}
	mutate(s)
	return s.Save(repoPath)
}
