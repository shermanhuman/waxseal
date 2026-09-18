package ops

import (
	"context"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
)

// ResealInput selects what to reseal.
type ResealInput struct {
	ShortNames []string // empty means every active secret
	DryRun     bool
	Progress   func(string)
}

// ResealResult is the outcome for one secret.
type ResealResult struct {
	ShortName string `json:"shortName"`
	Keys      int    `json:"keys"`
	Error     string `json:"error,omitempty"`
}

// Reseal re-encrypts secrets from their GSM values. One failing secret does
// not stop the others; the error is in its result.
func (s *Service) Reseal(ctx context.Context, in ResealInput) ([]ResealResult, error) {
	var targets []*core.SecretMetadata
	if len(in.ShortNames) == 0 {
		all, errs := s.Repo.AllMetadata()
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		for _, m := range all {
			if !m.IsRetired() {
				targets = append(targets, m)
			}
		}
	} else {
		for _, name := range in.ShortNames {
			m, err := s.activeMetadata(name)
			if err != nil {
				return nil, err
			}
			targets = append(targets, m)
		}
	}

	results := make([]ResealResult, 0, len(targets))
	for _, m := range targets {
		if in.Progress != nil {
			in.Progress(m.ShortName)
		}
		r := ResealResult{ShortName: m.ShortName, Keys: len(m.Keys)}
		if err := s.resealOne(ctx, m, in.DryRun); err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}
	return results, nil
}

func (s *Service) resealOne(ctx context.Context, m *core.SecretMetadata, dryRun bool) error {
	if s.Store == nil {
		return errors.New("GSM access is required")
	}
	values, err := s.materialize(ctx, m)
	if err != nil {
		return err
	}
	writes := make([]keyWrite, 0, len(values))
	for i := range m.Keys {
		k := &m.Keys[i]
		writes = append(writes, keyWrite{name: k.KeyName, seal: values[k.KeyName]})
	}
	_, err = s.apply(ctx, m, writes, true, dryRun)
	return err
}

// CertStatus compares the repo certificate with the controller's.
type CertStatus struct {
	RepoFingerprint    string `json:"repoFingerprint,omitempty"`
	ClusterFingerprint string `json:"clusterFingerprint"`
	Changed            bool   `json:"changed"`
	Updated            bool   `json:"updated"`
}

// RefreshCert fetches the controller's certificate and, when apply is set,
// stores it in the repo if it differs from the current one.
func (s *Service) RefreshCert(ctx context.Context, apply bool) (*CertStatus, error) {
	if s.Certs == nil {
		return nil, errors.New("fetching the certificate requires kubeseal and cluster access")
	}
	pemData, err := s.Certs.FetchCert(ctx, s.Config.Controller.Namespace, s.Config.Controller.ServiceName)
	if err != nil {
		return nil, err
	}
	cluster, err := seal.ParseCert(pemData)
	if err != nil {
		return nil, fmt.Errorf("controller certificate: %w", err)
	}
	st := &CertStatus{ClusterFingerprint: cluster.Fingerprint()}

	current, err := s.Repo.Cert(s.Config.Cert.RepoCertPath)
	switch {
	case err == nil:
		info, err := seal.ParseCert(current)
		if err == nil {
			st.RepoFingerprint = info.Fingerprint()
		}
	case !core.IsNotFound(err):
		return nil, err
	}
	st.Changed = st.RepoFingerprint != st.ClusterFingerprint
	if st.Changed && apply {
		if err := s.Repo.WriteCert(s.Config.Cert.RepoCertPath, pemData); err != nil {
			return nil, err
		}
		st.Updated = true
	}
	return st, nil
}
