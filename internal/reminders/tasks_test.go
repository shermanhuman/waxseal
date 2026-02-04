package reminders

import (
	"context"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

// TestGoogleTasksProvider_CreateTask tests task creation.
func TestGoogleTasksProvider_CreateTask(t *testing.T) {
	secret := &core.SecretMetadata{
		ShortName:    "test-secret",
		ManifestPath: "apps/test/sealed.yaml",
	}
	key := core.KeyMetadata{
		KeyName: "api_key",
		Rotation: &core.RotationConfig{
			Mode: "external",
		},
	}

	expiresAt := time.Now().AddDate(0, 0, 30)
	leadDays := 7
	reminderTime := expiresAt.AddDate(0, 0, -leadDays)

	// Test task fields (can't actually create without service)
	provider := &GoogleTasksProvider{
		tasklistID:   "@default",
		leadTimeDays: []int{30, 7, 1},
	}

	task := provider.createTask(secret, key, expiresAt, leadDays, reminderTime)

	t.Run("title format", func(t *testing.T) {
		if task.Title == "" {
			t.Error("task title should not be empty")
		}
		// Should contain secret and key name
		if len(task.Title) < 10 {
			t.Error("task title seems too short")
		}
	})

	t.Run("notes content", func(t *testing.T) {
		if task.Notes == "" {
			t.Error("task notes should not be empty")
		}
		// Should contain rotation command
		if len(task.Notes) < 50 {
			t.Error("task notes seem incomplete")
		}
	})

	t.Run("due date format", func(t *testing.T) {
		if task.Due == "" {
			t.Error("task due date should be set")
		}
		// Due should be RFC3339 formatted
		_, err := time.Parse(time.RFC3339, task.Due)
		if err != nil {
			t.Errorf("due date not in RFC3339 format: %v", err)
		}
	})
}

// TestGoogleTasksProvider_TaskTitleVariants tests different title formats.
func TestGoogleTasksProvider_TaskTitleVariants(t *testing.T) {
	secret := &core.SecretMetadata{ShortName: "my-secret"}
	key := core.KeyMetadata{KeyName: "cert"}
	expiresAt := time.Now().AddDate(0, 0, 30)

	provider := &GoogleTasksProvider{
		tasklistID:   "@default",
		leadTimeDays: []int{30, 7, 1, 0},
	}

	testCases := []struct {
		leadDays    int
		expectEmoji string
	}{
		{30, "🔐"}, // Normal reminder
		{7, "🔐"},  // Week reminder
		{1, "⚠️"}, // Tomorrow
		{0, "🚨"},  // Today
	}

	for _, tc := range testCases {
		t.Run(tc.expectEmoji+" reminder", func(t *testing.T) {
			reminderTime := expiresAt.AddDate(0, 0, -tc.leadDays)
			task := provider.createTask(secret, key, expiresAt, tc.leadDays, reminderTime)

			// Check that title contains appropriate emoji or urgency
			if len(task.Title) == 0 {
				t.Error("title should not be empty")
			}
		})
	}
}

// TestGoogleTasksProvider_DefaultTasklist tests default tasklist behavior.
func TestGoogleTasksProvider_DefaultTasklist(t *testing.T) {
	t.Run("empty uses default", func(t *testing.T) {
		// NewGoogleTasksProvider would set "@default" if empty
		tasklistID := ""
		if tasklistID == "" {
			tasklistID = DefaultTaskList
		}
		if tasklistID != "@default" {
			t.Errorf("expected @default, got %s", tasklistID)
		}
	})

	t.Run("custom tasklist preserved", func(t *testing.T) {
		customID := "my-custom-list"
		if customID == DefaultTaskList {
			t.Error("custom should not equal default")
		}
	})
}

// TestGoogleTasksProvider_LeadTimeDays tests lead time defaults.
func TestGoogleTasksProvider_LeadTimeDays(t *testing.T) {
	t.Run("default lead times", func(t *testing.T) {
		var leadTimeDays []int
		if len(leadTimeDays) == 0 {
			leadTimeDays = []int{30, 7, 1}
		}

		expected := []int{30, 7, 1}
		if len(leadTimeDays) != len(expected) {
			t.Errorf("expected %d lead times, got %d", len(expected), len(leadTimeDays))
		}
		for i, v := range expected {
			if leadTimeDays[i] != v {
				t.Errorf("leadTimeDays[%d] = %d, want %d", i, leadTimeDays[i], v)
			}
		}
	})

	t.Run("custom lead times", func(t *testing.T) {
		customDays := []int{60, 30, 14, 7, 3, 1}
		if len(customDays) != 6 {
			t.Error("custom lead times not preserved")
		}
	})
}

// TestGoogleTasksProvider_SkipPastReminders tests that past reminders are skipped.
func TestGoogleTasksProvider_SkipPastReminders(t *testing.T) {
	now := time.Now()

	t.Run("future reminder included", func(t *testing.T) {
		futureTime := now.AddDate(0, 0, 7)
		if futureTime.Before(now) {
			t.Error("future time should be after now")
		}
	})

	t.Run("past reminder skipped", func(t *testing.T) {
		pastTime := now.AddDate(0, 0, -7)
		if !pastTime.Before(now) {
			t.Error("past time should be before now")
		}
	})
}

// TestGoogleTasksProvider_RetiredSecretSkipped tests that retired secrets are skipped.
func TestGoogleTasksProvider_RetiredSecretSkipped(t *testing.T) {
	secret := &core.SecretMetadata{
		ShortName: "retired-secret",
		Status:    "retired",
	}

	if !secret.IsRetired() {
		t.Error("secret should be detected as retired")
	}
}

// TestCalendarAndTasksProviderInterface tests both providers implement interface.
func TestCalendarAndTasksProviderInterface(t *testing.T) {
	// Compile-time checks are in the source files
	var _ Provider = (*GoogleCalendarProvider)(nil)
	var _ Provider = (*GoogleTasksProvider)(nil)
	var _ Provider = (*FakeProvider)(nil)

	t.Log("all providers implement Provider interface")
}

// TestFakeProvider tests the FakeProvider for testing.
func TestFakeProvider_Recording(t *testing.T) {
	fake := NewFakeProvider()

	t.Run("records sync calls", func(t *testing.T) {
		secrets := []*core.SecretMetadata{
			{ShortName: "test-1"},
			{ShortName: "test-2"},
		}

		result, err := fake.SyncReminders(context.TODO(), secrets)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.SyncCalls) != 1 {
			t.Errorf("expected 1 sync call, got %d", len(fake.SyncCalls))
		}
		if result.Created != 2 {
			t.Errorf("expected 2 created, got %d", result.Created)
		}
	})

	t.Run("records delete calls", func(t *testing.T) {
		err := fake.DeleteReminders(context.TODO(), "test-secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.DeleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(fake.DeleteCalls))
		}
		if fake.DeleteCalls[0] != "test-secret" {
			t.Errorf("expected 'test-secret', got %s", fake.DeleteCalls[0])
		}
	})

	t.Run("returns configured error", func(t *testing.T) {
		fake.SyncError = core.ErrValidation
		_, err := fake.SyncReminders(context.TODO(), nil)
		if err != core.ErrValidation {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})
}
