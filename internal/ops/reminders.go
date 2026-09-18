package ops

import (
	"context"
	"errors"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/reminder"
)

// ExpiringSecrets returns the active secrets that have any key with an
// expiry date, which is what reminders are about.
func (s *Service) ExpiringSecrets() ([]*core.SecretMetadata, error) {
	all, errs := s.Repo.AllMetadata()
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var out []*core.SecretMetadata
	for _, m := range all {
		if m.IsRetired() {
			continue
		}
		for _, k := range m.Keys {
			if _, ok := k.ExpiresAt(); ok {
				out = append(out, m)
				break
			}
		}
	}
	return out, nil
}

// SyncResult reports a reminder sync.
type SyncResult struct {
	Secrets []string `json:"secrets"`
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors,omitempty"`
	DryRun  bool     `json:"dryRun"`
}

// SyncReminders pushes reminders for every expiring secret to the provider.
func (s *Service) SyncReminders(ctx context.Context, p reminder.Provider, dryRun bool) (*SyncResult, error) {
	secrets, err := s.ExpiringSecrets()
	if err != nil {
		return nil, err
	}
	res := &SyncResult{DryRun: dryRun}
	for _, m := range secrets {
		res.Secrets = append(res.Secrets, m.ShortName)
	}
	if dryRun || len(secrets) == 0 {
		return res, nil
	}
	r, err := p.SyncReminders(ctx, secrets)
	if err != nil {
		return nil, err
	}
	res.Created, res.Updated, res.Skipped = r.Created, r.Updated, r.Skipped
	for _, e := range r.Errors {
		res.Errors = append(res.Errors, e.Error())
	}
	return res, nil
}

// ClearReminders removes a secret's reminders from the provider.
func (s *Service) ClearReminders(ctx context.Context, p reminder.Provider, shortName string, dryRun bool) error {
	if _, err := s.metadata(shortName); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	return p.DeleteReminders(ctx, shortName)
}
