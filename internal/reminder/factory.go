package reminder

import (
	"context"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
)

// ErrDisabled is returned by New when reminders are not enabled in config.
var ErrDisabled = errors.New("reminders are not enabled in config")

// New builds the provider selected by config. "both" fans out to Tasks and
// Calendar. A disabled or "none" config yields ErrDisabled.
func New(ctx context.Context, cfg *config.RemindersConfig) (Provider, error) {
	if cfg == nil || !cfg.Enabled || cfg.Provider == "none" {
		return nil, ErrDisabled
	}
	switch cfg.Provider {
	case "tasks", "":
		return NewGoogleTasksProvider(ctx, cfg.TasklistID, cfg.LeadTimeDays)
	case "calendar":
		return NewGoogleCalendarProvider(ctx, cfg.CalendarID, cfg.LeadTimeDays)
	case "both":
		tasks, err := NewGoogleTasksProvider(ctx, cfg.TasklistID, cfg.LeadTimeDays)
		if err != nil {
			return nil, err
		}
		cal, err := NewGoogleCalendarProvider(ctx, cfg.CalendarID, cfg.LeadTimeDays)
		if err != nil {
			return nil, err
		}
		return Multi{tasks, cal}, nil
	default:
		return nil, fmt.Errorf("unknown reminders provider %q", cfg.Provider)
	}
}

// Multi fans every call out to each provider and merges the results.
type Multi []Provider

// SyncReminders syncs to every provider; per-provider failures are collected
// in the result rather than aborting the others.
func (m Multi) SyncReminders(ctx context.Context, secrets []*core.SecretMetadata) (*SyncResult, error) {
	total := &SyncResult{}
	for _, p := range m {
		r, err := p.SyncReminders(ctx, secrets)
		if err != nil {
			total.Errors = append(total.Errors, err)
			continue
		}
		total.Created += r.Created
		total.Updated += r.Updated
		total.Skipped += r.Skipped
		total.Errors = append(total.Errors, r.Errors...)
	}
	return total, nil
}

// DeleteReminders deletes from every provider and returns the errors joined.
func (m Multi) DeleteReminders(ctx context.Context, shortName string) error {
	var errs []error
	for _, p := range m {
		if err := p.DeleteReminders(ctx, shortName); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

var _ Provider = Multi(nil)
