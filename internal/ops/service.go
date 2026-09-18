// Package ops implements waxseal's use cases. Operations take everything
// they need up front, return plain data, and never print, prompt, or read
// flags or the environment: the CLI does that, tests use fakes.
package ops

import (
	"context"
	"fmt"
	"time"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

// Cluster is what ops need from Kubernetes.
type Cluster interface {
	GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error)
}

// CertFetcher obtains the controller's current sealing certificate.
type CertFetcher interface {
	FetchCert(ctx context.Context, controllerNamespace, controllerName string) ([]byte, error)
}

// Service holds the ports an operation may use. A nil port means that
// capability is unavailable; operations that need it say so rather than
// panicking, and checks report it as skipped.
type Service struct {
	Repo    *repo.Repo
	Config  *config.Config
	Store   store.Store
	Sealer  seal.Sealer
	Cluster Cluster
	Certs   CertFetcher
	// Now supplies the current time; tests fix it. Defaults to time.Now.
	Now func() time.Time
	// ProjectID is the GCP project new GSM secrets are created in.
	ProjectID string
}

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Change is one side effect an operation made or, in a dry run, would make.
type Change struct {
	Op     string `json:"op"`     // create | update | delete
	Kind   string `json:"kind"`   // gsm-version | gsm-secret | metadata | manifest | cert | config | reminder
	Target string `json:"target"` // path, GSM resource, or item name; never a secret value
}

func (c Change) String() string { return fmt.Sprintf("%s %s %s", c.Op, c.Kind, c.Target) }
