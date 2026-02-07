package reminder

import (
	"context"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestFakeProvider_SyncReminders(t *testing.T) {
	provider := NewFakeProvider()

	secrets := []*core.SecretMetadata{
		{ShortName: "test-secret-1"},
		{ShortName: "test-secret-2"},
	}

	result, err := provider.SyncReminders(context.Background(), secrets)
	if err != nil {
		t.Fatalf("SyncReminders failed: %v", err)
	}

	if result.Created != 2 {
		t.Errorf("Created = %d, want 2", result.Created)
	}

	if len(provider.SyncCalls) != 1 {
		t.Errorf("SyncCalls = %d, want 1", len(provider.SyncCalls))
	}
}

func TestFakeProvider_DeleteReminders(t *testing.T) {
	provider := NewFakeProvider()

	err := provider.DeleteReminders(context.Background(), "test-secret")
	if err != nil {
		t.Fatalf("DeleteReminders failed: %v", err)
	}

	if len(provider.DeleteCalls) != 1 {
		t.Errorf("DeleteCalls = %d, want 1", len(provider.DeleteCalls))
	}

	if provider.DeleteCalls[0] != "test-secret" {
		t.Errorf("DeleteCalls[0] = %q, want %q", provider.DeleteCalls[0], "test-secret")
	}
}

func TestGenerateEventID(t *testing.T) {
	tests := []struct {
		shortName string
		keyName   string
		leadDays  int
		wantLen   int // Just check length > 0
	}{
		{"my-secret", "password", 30, 10},
		{"MY-SECRET", "PASSWORD", 7, 10},
		{"test_secret", "api_key", 1, 10},
	}

	for _, tt := range tests {
		id := generateEventID(tt.shortName, tt.keyName, tt.leadDays)
		if len(id) < tt.wantLen {
			t.Errorf("generateEventID(%q, %q, %d) = %q, length too short", tt.shortName, tt.keyName, tt.leadDays, id)
		}

		// Should be all lowercase alphanumeric
		for _, c := range id {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				t.Errorf("generateEventID produced invalid character: %c in %q", c, id)
			}
		}
	}
}

func TestGetRotationMode(t *testing.T) {
	tests := []struct {
		key  core.KeyMetadata
		want string
	}{
		{core.KeyMetadata{}, "none"},
		{core.KeyMetadata{Rotation: &core.RotationConfig{Mode: "generated"}}, "generated"},
		{core.KeyMetadata{Rotation: &core.RotationConfig{Mode: "external"}}, "external"},
	}

	for _, tt := range tests {
		got := getRotationMode(tt.key)
		if got != tt.want {
			t.Errorf("getRotationMode() = %q, want %q", got, tt.want)
		}
	}
}

func TestSecretWithExpiry(t *testing.T) {
	// Test that we can identify secrets with expiry
	expiresAt := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)

	secret := &core.SecretMetadata{
		ShortName: "tls-cert",
		Keys: []core.KeyMetadata{
			{
				KeyName: "tls.crt",
				Expiry: &core.ExpiryConfig{
					ExpiresAt: expiresAt,
				},
			},
		},
	}

	if secret.Keys[0].Expiry == nil {
		t.Error("expected expiry config")
	}

	_, err := time.Parse(time.RFC3339, secret.Keys[0].Expiry.ExpiresAt)
	if err != nil {
		t.Errorf("invalid expiry format: %v", err)
	}
}
