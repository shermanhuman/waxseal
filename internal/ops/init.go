package ops

import (
	"cmp"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/repo"
)

// InitInput describes a new repository configuration.
type InitInput struct {
	ProjectID           string
	ControllerNamespace string // default kube-system
	ControllerName      string // default sealed-secrets
	Force               bool   // overwrite an existing config
	DryRun              bool
}

// ErrAlreadyInitialised is returned when a config exists and Force is not set.
var ErrAlreadyInitialised = errors.New("already initialised; pass --force to overwrite the config")

// Init writes .waxseal/config.yaml. It touches nothing else: the
// certificate is fetched by RefreshCert and secrets are registered by Import
// or AddKey.
func (s *Service) Init(in InitInput) (*MutationResult, error) {
	if in.ProjectID == "" {
		return nil, &core.MissingInputError{Field: "--project"}
	}
	_, err := s.Repo.Config()
	switch {
	case err == nil && !in.Force:
		return nil, fmt.Errorf("%s: %w", s.Repo.ConfigPath(), ErrAlreadyInitialised)
	case err != nil && !core.IsNotFound(err) && !in.Force:
		return nil, err
	}
	cfg := &config.Config{
		Version: "1",
		Store:   config.StoreConfig{Kind: "gsm", ProjectID: in.ProjectID},
		Controller: config.ControllerConfig{
			Namespace:   cmp.Or(in.ControllerNamespace, "kube-system"),
			ServiceName: cmp.Or(in.ControllerName, "sealed-secrets"),
		},
		Cert: config.CertConfig{RepoCertPath: "keys/pub-cert.pem"},
	}
	res := &MutationResult{DryRun: in.DryRun, Changes: []Change{{Op: "create", Kind: "config", Target: repo.ConfigRel}}}
	if in.DryRun {
		return res, nil
	}
	if err := s.Repo.WriteConfig(cfg); err != nil {
		return nil, err
	}
	return res, nil
}
