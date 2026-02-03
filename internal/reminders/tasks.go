// Package reminders provides task and calendar integration for expiry alerts.
package reminders

import (
	"context"
	"fmt"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/logging"
	"google.golang.org/api/option"
	"google.golang.org/api/tasks/v1"
)

// DefaultTaskList is the special identifier for user's primary task list.
// Tasks created here automatically appear in Google Calendar.
const DefaultTaskList = "@default"

// GoogleTasksProvider implements Provider using Google Tasks API.
// Tasks with due dates automatically appear in Google Calendar.
type GoogleTasksProvider struct {
	tasklistID   string
	leadTimeDays []int
	service      *tasks.Service
}

// NewGoogleTasksProvider creates a provider using Application Default Credentials.
// If tasklistID is empty, uses "@default" (user's primary task list).
func NewGoogleTasksProvider(ctx context.Context, tasklistID string, leadTimeDays []int) (*GoogleTasksProvider, error) {
	service, err := tasks.NewService(ctx, option.WithScopes(tasks.TasksScope))
	if err != nil {
		return nil, fmt.Errorf("create tasks service: %w", err)
	}

	if tasklistID == "" {
		tasklistID = DefaultTaskList
	}

	if len(leadTimeDays) == 0 {
		leadTimeDays = []int{30, 7, 1} // Default: 30 days, 7 days, 1 day before
	}

	return &GoogleTasksProvider{
		tasklistID:   tasklistID,
		leadTimeDays: leadTimeDays,
		service:      service,
	}, nil
}

// SyncReminders creates tasks for secrets with expiry dates.
// Tasks with due dates automatically appear in Google Calendar.
func (p *GoogleTasksProvider) SyncReminders(ctx context.Context, secrets []*core.SecretMetadata) (*SyncResult, error) {
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

			// Create reminder tasks for each lead time
			for _, days := range p.leadTimeDays {
				reminderTime := expiresAt.AddDate(0, 0, -days)

				// Skip if reminder time is in the past
				if reminderTime.Before(time.Now()) {
					continue
				}

				task := p.createTask(secret, key, expiresAt, days, reminderTime)

				// Check if task already exists by listing and matching title
				existing, err := p.findExistingTask(ctx, task.Title)
				if err != nil {
					logging.Warn("failed to check for existing task",
						"title", task.Title,
						"error", err.Error(),
					)
				}

				if existing != nil {
					// Update existing task
					task.Id = existing.Id
					_, err = p.service.Tasks.Update(p.tasklistID, existing.Id, task).Context(ctx).Do()
					if err != nil {
						result.Errors = append(result.Errors, fmt.Errorf("update task %s: %w", task.Title, err))
					} else {
						result.Updated++
					}
				} else {
					// Create new task
					_, err = p.service.Tasks.Insert(p.tasklistID, task).Context(ctx).Do()
					if err != nil {
						result.Errors = append(result.Errors, fmt.Errorf("create task %s: %w", task.Title, err))
					} else {
						result.Created++
					}
				}
			}
		}
	}

	return result, nil
}

// DeleteReminders removes all tasks for a secret.
func (p *GoogleTasksProvider) DeleteReminders(ctx context.Context, shortName string) error {
	prefix := fmt.Sprintf("🔐 %s/", shortName)

	// List all tasks and find ones matching our prefix
	taskList, err := p.service.Tasks.List(p.tasklistID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("list tasks: %w", err)
	}

	for _, task := range taskList.Items {
		if len(task.Title) >= len(prefix) && task.Title[:len(prefix)] == prefix {
			if err := p.service.Tasks.Delete(p.tasklistID, task.Id).Context(ctx).Do(); err != nil {
				logging.Warn("failed to delete task",
					"taskId", task.Id,
					"error", err.Error(),
				)
			}
		}
	}

	return nil
}

func (p *GoogleTasksProvider) createTask(secret *core.SecretMetadata, key core.KeyMetadata, expiresAt time.Time, leadDays int, reminderTime time.Time) *tasks.Task {
	title := fmt.Sprintf("🔐 %s/%s - Rotate in %d days", secret.ShortName, key.KeyName, leadDays)
	if leadDays == 0 {
		title = fmt.Sprintf("🚨 %s/%s - EXPIRES TODAY", secret.ShortName, key.KeyName)
	} else if leadDays == 1 {
		title = fmt.Sprintf("⚠️ %s/%s - Expires TOMORROW", secret.ShortName, key.KeyName)
	}

	notes := fmt.Sprintf(`Secret Expiration Reminder

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

	return &tasks.Task{
		Title: title,
		Notes: notes,
		// Due date in RFC3339 format - this makes tasks appear in Calendar
		Due: reminderTime.Format(time.RFC3339),
	}
}

func (p *GoogleTasksProvider) findExistingTask(ctx context.Context, title string) (*tasks.Task, error) {
	taskList, err := p.service.Tasks.List(p.tasklistID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, task := range taskList.Items {
		if task.Title == title {
			return task, nil
		}
	}
	return nil, nil
}

// Compile-time interface check
var _ Provider = (*GoogleTasksProvider)(nil)
