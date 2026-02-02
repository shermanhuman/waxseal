// Package reminders provides calendar integration for expiry alerts.
package reminders

import (
	"context"
	"fmt"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/logging"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

// Provider manages calendar reminders for secret expiration.
type Provider interface {
	// SyncReminders creates or updates calendar events for expiring secrets.
	SyncReminders(ctx context.Context, secrets []*core.SecretMetadata) (*SyncResult, error)
	// DeleteReminders removes calendar events for a secret.
	DeleteReminders(ctx context.Context, shortName string) error
}

// SyncResult contains the result of a reminder sync operation.
type SyncResult struct {
	Created int
	Updated int
	Skipped int
	Errors  []error
}

// GoogleCalendarProvider implements Provider using Google Calendar API.
type GoogleCalendarProvider struct {
	calendarID   string
	leadTimeDays []int
	service      *calendar.Service
}

// NewGoogleCalendarProvider creates a provider using Application Default Credentials.
func NewGoogleCalendarProvider(ctx context.Context, calendarID string, leadTimeDays []int) (*GoogleCalendarProvider, error) {
	// Use ADC for authentication
	service, err := calendar.NewService(ctx, option.WithScopes(calendar.CalendarEventsScope))
	if err != nil {
		return nil, fmt.Errorf("create calendar service: %w", err)
	}

	if len(leadTimeDays) == 0 {
		leadTimeDays = []int{30, 7, 1} // Default: 30 days, 7 days, 1 day before
	}

	return &GoogleCalendarProvider{
		calendarID:   calendarID,
		leadTimeDays: leadTimeDays,
		service:      service,
	}, nil
}

// SyncReminders creates calendar events for secrets with expiry dates.
func (p *GoogleCalendarProvider) SyncReminders(ctx context.Context, secrets []*core.SecretMetadata) (*SyncResult, error) {
	result := &SyncResult{}

	for _, secret := range secrets {
		if secret.IsRetired() {
			result.Skipped++
			continue
		}

		// Check each key for expiry
		for _, key := range secret.Keys {
			if key.Expiry == nil || key.Expiry.ExpiresAt == "" {
				continue
			}

			expiresAt, err := time.Parse(time.RFC3339, key.Expiry.ExpiresAt)
			if err != nil {
				logging.Warn("invalid expiry date",
					"secret", secret.ShortName,
					"key", key.KeyName,
					"expiresAt", key.Expiry.ExpiresAt,
				)
				continue
			}

			// Create reminder events for each lead time
			for _, days := range p.leadTimeDays {
				reminderTime := expiresAt.AddDate(0, 0, -days)

				// Skip if reminder time is in the past
				if reminderTime.Before(time.Now()) {
					continue
				}

				eventID := generateEventID(secret.ShortName, key.KeyName, days)
				event := p.createEvent(secret, key, expiresAt, days)

				// Check if event exists
				existing, err := p.service.Events.Get(p.calendarID, eventID).Context(ctx).Do()
				if err == nil && existing != nil {
					// Update existing event
					_, err = p.service.Events.Update(p.calendarID, eventID, event).Context(ctx).Do()
					if err != nil {
						result.Errors = append(result.Errors, fmt.Errorf("update event %s: %w", eventID, err))
					} else {
						result.Updated++
					}
				} else {
					// Create new event
					event.Id = eventID
					_, err = p.service.Events.Insert(p.calendarID, event).Context(ctx).Do()
					if err != nil {
						result.Errors = append(result.Errors, fmt.Errorf("create event %s: %w", eventID, err))
					} else {
						result.Created++
					}
				}
			}
		}
	}

	return result, nil
}

// DeleteReminders removes all calendar events for a secret.
func (p *GoogleCalendarProvider) DeleteReminders(ctx context.Context, shortName string) error {
	// List events with our prefix
	prefix := "waxseal-" + shortName

	events, err := p.service.Events.List(p.calendarID).
		Q(prefix).
		Context(ctx).
		Do()
	if err != nil {
		return fmt.Errorf("list events: %w", err)
	}

	for _, event := range events.Items {
		if err := p.service.Events.Delete(p.calendarID, event.Id).Context(ctx).Do(); err != nil {
			logging.Warn("failed to delete event",
				"eventId", event.Id,
				"error", err.Error(),
			)
		}
	}

	return nil
}

func (p *GoogleCalendarProvider) createEvent(secret *core.SecretMetadata, key core.KeyMetadata, expiresAt time.Time, leadDays int) *calendar.Event {
	reminderTime := expiresAt.AddDate(0, 0, -leadDays)

	summary := fmt.Sprintf("🔐 Secret Expiring: %s/%s", secret.ShortName, key.KeyName)
	if leadDays == 0 {
		summary = fmt.Sprintf("🚨 Secret Expires TODAY: %s/%s", secret.ShortName, key.KeyName)
	}

	description := fmt.Sprintf(`Secret Expiration Reminder

Secret: %s
Key: %s
Expires: %s
Lead Time: %d days

Rotation Mode: %s

To rotate:
  waxseal rotate %s %s

Manifest: %s
`,
		secret.ShortName,
		key.KeyName,
		expiresAt.Format("2006-01-02 15:04 MST"),
		leadDays,
		getRotationMode(key),
		secret.ShortName,
		key.KeyName,
		secret.ManifestPath,
	)

	return &calendar.Event{
		Summary:     summary,
		Description: description,
		Start: &calendar.EventDateTime{
			Date: reminderTime.Format("2006-01-02"),
		},
		End: &calendar.EventDateTime{
			Date: reminderTime.Format("2006-01-02"),
		},
		Reminders: &calendar.EventReminders{
			UseDefault: false,
			Overrides: []*calendar.EventReminder{
				{Method: "popup", Minutes: 0},
				{Method: "email", Minutes: 60},
			},
		},
	}
}

func generateEventID(shortName, keyName string, leadDays int) string {
	// Calendar event IDs must be lowercase alphanumeric
	id := fmt.Sprintf("waxseal-%s-%s-%dd", shortName, keyName, leadDays)
	// Replace invalid characters
	result := make([]byte, 0, len(id))
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, byte(c))
		} else if c >= 'A' && c <= 'Z' {
			result = append(result, byte(c-'A'+'a'))
		}
	}
	return string(result)
}

func getRotationMode(key core.KeyMetadata) string {
	if key.Rotation == nil {
		return "none"
	}
	return key.Rotation.Mode
}

// FakeProvider is a test implementation that records calls.
type FakeProvider struct {
	SyncCalls   []SyncCall
	DeleteCalls []string
	SyncError   error
	DeleteError error
}

type SyncCall struct {
	Secrets []*core.SecretMetadata
}

func NewFakeProvider() *FakeProvider {
	return &FakeProvider{}
}

func (f *FakeProvider) SyncReminders(ctx context.Context, secrets []*core.SecretMetadata) (*SyncResult, error) {
	f.SyncCalls = append(f.SyncCalls, SyncCall{Secrets: secrets})
	if f.SyncError != nil {
		return nil, f.SyncError
	}
	return &SyncResult{Created: len(secrets)}, nil
}

func (f *FakeProvider) DeleteReminders(ctx context.Context, shortName string) error {
	f.DeleteCalls = append(f.DeleteCalls, shortName)
	return f.DeleteError
}

// Compile-time interface checks
var (
	_ Provider = (*GoogleCalendarProvider)(nil)
	_ Provider = (*FakeProvider)(nil)
)
