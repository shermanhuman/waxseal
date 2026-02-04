// Package template provides integration tests for GSM JSON payloads.
// These tests require:
// - GCP project: waxseal-test
// - GOOGLE_APPLICATION_CREDENTIALS set
// - Secret Manager API enabled
//
// Run with: go test -v -tags=integration ./internal/template/...
//
//go:build integration

package template

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/store"
)

const testProject = "waxseal-test"

func TestGSMPayloadIntegration(t *testing.T) {
	ctx := context.Background()

	// Create GSM store
	gsmStore, err := store.NewGSMStore(ctx, testProject)
	if err != nil {
		t.Skipf("Skipping GSM integration test: %v", err)
	}
	defer gsmStore.Close()

	// Generate unique secret name for this test run
	secretName := fmt.Sprintf("test-payload-%d", time.Now().UnixNano())
	secretResource := store.SecretResource(testProject, secretName)

	t.Run("CreatePayload", func(t *testing.T) {
		// Create a templated payload
		payload, err := NewPayload(
			"postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
			map[string]string{
				"username": "testuser",
				"host":     "localhost",
				"port":     "5432",
				"database": "testdb",
			},
			"initial-secret-value",
			&GeneratorConfig{Kind: "randomBase64", Bytes: 32},
		)
		if err != nil {
			t.Fatalf("NewPayload() error = %v", err)
		}

		// Verify computed value
		expected := "postgresql://testuser:initial-secret-value@localhost:5432/testdb"
		if payload.Computed != expected {
			t.Errorf("Computed = %q, want %q", payload.Computed, expected)
		}

		// Marshal and store in GSM
		data, err := payload.Marshal()
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		version, err := gsmStore.CreateSecretVersion(ctx, secretResource, data)
		if err != nil {
			t.Fatalf("CreateSecretVersion() error = %v", err)
		}
		t.Logf("Created GSM version: %s", version)
	})

	t.Run("ReadAndRotate", func(t *testing.T) {
		// Read payload from GSM
		data, err := gsmStore.AccessVersion(ctx, secretResource, "latest")
		if err != nil {
			t.Fatalf("AccessVersion() error = %v", err)
		}

		payload, err := ParsePayload(data)
		if err != nil {
			t.Fatalf("ParsePayload() error = %v", err)
		}

		// Verify we got the right payload
		if payload.Values["username"] != "testuser" {
			t.Errorf("username = %q, want testuser", payload.Values["username"])
		}

		// Simulate rotation: update secret
		newSecret := "rotated-secret-value-12345678"
		if err := payload.UpdateSecret(newSecret); err != nil {
			t.Fatalf("UpdateSecret() error = %v", err)
		}

		// Verify computed updated
		if payload.Computed != "postgresql://testuser:rotated-secret-value-12345678@localhost:5432/testdb" {
			t.Errorf("Computed after rotation = %q", payload.Computed)
		}

		// Store new version
		data, _ = payload.Marshal()
		newVersion, err := gsmStore.AddVersion(ctx, secretResource, data)
		if err != nil {
			t.Fatalf("AddVersion() error = %v", err)
		}
		t.Logf("Added rotated version: %s", newVersion)

		// Verify we can read the new version
		data2, err := gsmStore.AccessVersion(ctx, secretResource, "latest")
		if err != nil {
			t.Fatalf("AccessVersion(latest) after rotation error = %v", err)
		}

		payload2, _ := ParsePayload(data2)
		if payload2.Secret != newSecret {
			t.Errorf("Secret after re-read = %q, want %q", payload2.Secret, newSecret)
		}
	})

	// Note: We don't delete test secrets to allow inspection
	// They should be cleaned up manually or by a scheduled task
	t.Logf("Test secret: %s (clean up manually)", secretResource)
}

func TestPasswordLengthCompatibility(t *testing.T) {
	// Test that our default 32-byte base64 password (44 chars) works for all DB types
	tests := []struct {
		name        string
		template    string
		maxPassLen  int // 0 means no limit
		description string
	}{
		{
			name:        "PostgreSQL",
			template:    "postgresql://user:{{secret}}@host:5432/db",
			maxPassLen:  1024, // scram-sha-256
			description: "PostgreSQL SCRAM-SHA-256 auth supports up to 1024 chars",
		},
		{
			name:        "MySQL",
			template:    "mysql://user:{{secret}}@host:3306/db",
			maxPassLen:  255, // recommended max
			description: "MySQL recommended max ~255 chars",
		},
		{
			name:        "Redis",
			template:    "redis://:{{secret}}@host:6379/0",
			maxPassLen:  0, // no limit
			description: "Redis has no password length limit",
		},
		{
			name:        "MongoDB",
			template:    "mongodb://user:{{secret}}@host:27017/db",
			maxPassLen:  0, // no explicit limit
			description: "MongoDB has no explicit password length limit",
		},
	}

	// Our default: 32 bytes base64 = 44 characters
	defaultSecretLen := 44

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify our default fits within the limit
			if tt.maxPassLen > 0 && defaultSecretLen > tt.maxPassLen {
				t.Errorf("Default secret length %d exceeds %s max of %d: %s",
					defaultSecretLen, tt.name, tt.maxPassLen, tt.description)
			}

			// Verify template computes correctly
			payload, err := NewPayload(tt.template, map[string]string{}, "test-secret", nil)
			if err != nil {
				t.Errorf("NewPayload() error = %v", err)
			}

			// Verify {{secret}} was replaced
			if payload.Computed == tt.template {
				t.Errorf("Template was not computed (still contains {{secret}})")
			}

			t.Logf("%s: max=%d, our default=%d - %s", tt.name,
				tt.maxPassLen, defaultSecretLen, tt.description)
		})
	}
}
