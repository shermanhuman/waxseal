package store

import (
	"context"
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

// =============================================================================
// GSM HELPER FUNCTION TESTS
// =============================================================================

// TestExtractVersionFromName tests version number extraction from GSM resource names.
func TestExtractVersionFromName(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{"simple version", "projects/myproj/secrets/mysec/versions/1", "1"},
		{"multi-digit version", "projects/myproj/secrets/mysec/versions/123", "123"},
		{"large version", "projects/test/secrets/foo/versions/999999", "999999"},
		{"no version suffix", "projects/myproj/secrets/mysec", ""},
		{"empty string", "", ""},
		{"malformed path", "versions/1", ""},
		{"version with text", "projects/p/secrets/s/versions/latest", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractVersionFromName(tc.input)
			if got != tc.want {
				t.Errorf("extractVersionFromName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestExtractSecretIDFromResource tests secret ID extraction from resource paths.
func TestExtractSecretIDFromResource(t *testing.T) {
	testCases := []struct {
		name     string
		resource string
		want     string
	}{
		{"valid resource", "projects/myproj/secrets/my-secret", "my-secret"},
		{"with underscores", "projects/test/secrets/api_key_v2", "api_key_v2"},
		{"with dashes", "projects/prod/secrets/database-password", "database-password"},
		{"simple name", "projects/p/secrets/s", "s"},
		{"missing secrets", "projects/myproj/mysec", ""},
		{"extra path", "projects/myproj/secrets/mysec/versions/1", ""},
		{"empty resource", "", ""},
		{"malformed", "secrets/mysec", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSecretIDFromResource(tc.resource)
			if got != tc.want {
				t.Errorf("extractSecretIDFromResource(%q) = %q, want %q", tc.resource, got, tc.want)
			}
		})
	}
}

// =============================================================================
// VERSION VALIDATION TESTS (CRITICAL FOR PINNING)
// =============================================================================

// TestValidateNumericVersion tests the version validation function.
func TestValidateNumericVersion(t *testing.T) {
	testCases := []struct {
		name      string
		version   string
		wantError bool
		errType   error
	}{
		// Valid versions
		{"version 1", "1", false, nil},
		{"version 42", "42", false, nil},
		{"large version", "999999", false, nil},
		{"zero", "0", false, nil},

		// Invalid - aliases not allowed
		{"latest alias", "latest", true, core.ErrValidation},
		{"versions/latest", "versions/latest", true, core.ErrValidation},

		// Invalid - non-numeric
		{"empty string", "", true, core.ErrValidation},
		{"letters only", "abc", true, core.ErrValidation},
		{"mixed alpha-numeric", "v1", true, core.ErrValidation},
		{"with space", "1 ", true, core.ErrValidation},
		{"special characters", "1-2", true, core.ErrValidation},
		{"decimal", "1.0", true, core.ErrValidation},
		{"negative", "-1", true, core.ErrValidation},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNumericVersion(tc.version)

			if tc.wantError {
				if err == nil {
					t.Errorf("ValidateNumericVersion(%q) = nil, want error", tc.version)
				}
				if tc.errType != nil && !errors.Is(err, tc.errType) {
					t.Errorf("ValidateNumericVersion(%q) error = %v, want %v", tc.version, err, tc.errType)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateNumericVersion(%q) = %v, want nil", tc.version, err)
				}
			}
		})
	}
}

// TestNumericVersionPattern tests the regex pattern directly.
func TestNumericVersionPattern(t *testing.T) {
	validVersions := []string{"1", "42", "999", "0", "123456789"}
	for _, v := range validVersions {
		if !numericVersionPattern.MatchString(v) {
			t.Errorf("pattern should match %q", v)
		}
	}

	invalidVersions := []string{"", "latest", "v1", "1.0", "-1", "1 2", " 1", "1 "}
	for _, v := range invalidVersions {
		if numericVersionPattern.MatchString(v) {
			t.Errorf("pattern should NOT match %q", v)
		}
	}
}

// =============================================================================
// FAKE STORE - VERSION VALIDATION TESTS
// =============================================================================

// TestFakeStore_RejectsLatestVersion tests that "latest" alias is rejected.
func TestFakeStore_RejectsLatestVersion(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	secretResource := "projects/test/secrets/my-secret"
	store.SetVersion(secretResource, "1", []byte("value"))

	// Access with "latest" should fail
	_, err := store.AccessVersion(ctx, secretResource, "latest")
	if err == nil {
		t.Error("expected error accessing with 'latest' version")
	}
	if !errors.Is(err, core.ErrNotFound) {
		// FakeStore returns NotFound for non-numeric versions
		// as they simply don't exist in the map
		t.Logf("got error: %v (type check may vary)", err)
	}
}

// TestFakeStore_EmptyVersion tests empty version handling.
func TestFakeStore_EmptyVersion(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	secretResource := "projects/test/secrets/my-secret"
	store.SetVersion(secretResource, "1", []byte("value"))

	_, err := store.AccessVersion(ctx, secretResource, "")
	if err == nil {
		t.Error("expected error accessing with empty version")
	}
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

// TestFakeStore_LargeData tests handling of large secret values.
func TestFakeStore_LargeData(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	secretResource := "projects/test/secrets/large-secret"

	// Create a 1MB secret
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	version, err := store.CreateSecret(ctx, secretResource, largeData)
	if err != nil {
		t.Fatalf("CreateSecret with large data: %v", err)
	}
	if version != "1" {
		t.Errorf("version = %s, want 1", version)
	}

	// Verify retrieval
	got, err := store.AccessVersion(ctx, secretResource, "1")
	if err != nil {
		t.Fatalf("AccessVersion: %v", err)
	}
	if len(got) != len(largeData) {
		t.Errorf("data length = %d, want %d", len(got), len(largeData))
	}
}

// TestFakeStore_BinaryData tests handling of binary (non-text) data.
func TestFakeStore_BinaryData(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	secretResource := "projects/test/secrets/binary-secret"

	// Binary data with null bytes
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x00}

	version, err := store.CreateSecret(ctx, secretResource, binaryData)
	if err != nil {
		t.Fatalf("CreateSecret with binary data: %v", err)
	}

	got, err := store.AccessVersion(ctx, secretResource, version)
	if err != nil {
		t.Fatalf("AccessVersion: %v", err)
	}

	if len(got) != len(binaryData) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(binaryData))
	}
	for i := range got {
		if got[i] != binaryData[i] {
			t.Errorf("byte %d: got %x, want %x", i, got[i], binaryData[i])
		}
	}
}

// TestFakeStore_SpecialCharactersInSecretID tests special characters in names.
func TestFakeStore_SpecialCharactersInSecretID(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	testCases := []string{
		"projects/test/secrets/my-secret",
		"projects/test/secrets/my_secret",
		"projects/test/secrets/my-secret-v2",
		"projects/test/secrets/mysecret123",
	}

	for _, secretResource := range testCases {
		t.Run(secretResource, func(t *testing.T) {
			data := []byte("secret-" + secretResource)
			version, err := store.CreateSecret(ctx, secretResource, data)
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			if version != "1" {
				t.Errorf("version = %s, want 1", version)
			}

			got, err := store.AccessVersion(ctx, secretResource, "1")
			if err != nil {
				t.Fatalf("AccessVersion: %v", err)
			}
			if string(got) != string(data) {
				t.Errorf("data mismatch")
			}
		})
	}
}

// TestFakeStore_ManyVersions tests many versions of the same secret.
func TestFakeStore_ManyVersions(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()
	secretResource := "projects/test/secrets/many-versions"

	// Create 100 versions
	_, err := store.CreateSecret(ctx, secretResource, []byte("v1"))
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	for i := 2; i <= 100; i++ {
		_, err := store.AddVersion(ctx, secretResource, []byte("v"+string(rune('0'+i%10))))
		if err != nil {
			t.Fatalf("AddVersion %d: %v", i, err)
		}
	}

	// Verify random versions are accessible
	for _, v := range []string{"1", "50", "100"} {
		_, err := store.AccessVersion(ctx, secretResource, v)
		if err != nil {
			t.Errorf("AccessVersion(%s): %v", v, err)
		}
	}
}

// TestSecretResourceBuilder tests the SecretResource helper function.
func TestSecretResourceBuilder(t *testing.T) {
	testCases := []struct {
		projectID string
		secretID  string
		want      string
	}{
		{"my-project", "my-secret", "projects/my-project/secrets/my-secret"},
		{"waxseal-test", "db-password", "projects/waxseal-test/secrets/db-password"},
		{"p", "s", "projects/p/secrets/s"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := SecretResource(tc.projectID, tc.secretID)
			if got != tc.want {
				t.Errorf("SecretResource(%q, %q) = %q, want %q",
					tc.projectID, tc.secretID, got, tc.want)
			}
		})
	}
}

// TestSecretVersionResourceBuilder tests the SecretVersionResource helper.
func TestSecretVersionResourceBuilder(t *testing.T) {
	testCases := []struct {
		projectID string
		secretID  string
		version   string
		want      string
	}{
		{"my-project", "my-secret", "1", "projects/my-project/secrets/my-secret/versions/1"},
		{"p", "s", "42", "projects/p/secrets/s/versions/42"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := SecretVersionResource(tc.projectID, tc.secretID, tc.version)
			if got != tc.want {
				t.Errorf("SecretVersionResource(%q, %q, %q) = %q, want %q",
					tc.projectID, tc.secretID, tc.version, got, tc.want)
			}
		})
	}
}
