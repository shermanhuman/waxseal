package store

import (
	"context"
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestFakeStore_CreateAndAccess(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"
	data := []byte("secret-value")

	// Create
	version, err := store.CreateSecret(ctx, secretResource, data)
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}
	if version != "1" {
		t.Errorf("version = %q, want %q", version, "1")
	}

	// Access
	got, err := store.AccessVersion(ctx, secretResource, "1")
	if err != nil {
		t.Fatalf("AccessVersion failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestFakeStore_AddVersion(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"

	// Create initial
	_, err := store.CreateSecret(ctx, secretResource, []byte("v1-value"))
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	// Add version
	version, err := store.AddVersion(ctx, secretResource, []byte("v2-value"))
	if err != nil {
		t.Fatalf("AddVersion failed: %v", err)
	}
	if version != "2" {
		t.Errorf("version = %q, want %q", version, "2")
	}

	// Verify both versions exist
	v1, _ := store.AccessVersion(ctx, secretResource, "1")
	if string(v1) != "v1-value" {
		t.Errorf("v1 = %q, want %q", v1, "v1-value")
	}

	v2, _ := store.AccessVersion(ctx, secretResource, "2")
	if string(v2) != "v2-value" {
		t.Errorf("v2 = %q, want %q", v2, "v2-value")
	}
}

func TestFakeStore_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	_, err := store.AccessVersion(ctx, "projects/test/secrets/nonexistent", "1")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
	if !errors.Is(err, core.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFakeStore_VersionNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"
	_, _ = store.CreateSecret(ctx, secretResource, []byte("v1"))

	_, err := store.AccessVersion(ctx, secretResource, "999")
	if err == nil {
		t.Fatal("expected error for nonexistent version")
	}
	if !errors.Is(err, core.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFakeStore_AlreadyExists(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"
	_, _ = store.CreateSecret(ctx, secretResource, []byte("v1"))

	_, err := store.CreateSecret(ctx, secretResource, []byte("v2"))
	if err == nil {
		t.Fatal("expected error for duplicate create")
	}
	if !errors.Is(err, core.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestFakeStore_AddVersionToNonexistent(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	_, err := store.AddVersion(ctx, "projects/test/secrets/nonexistent", []byte("data"))
	if err == nil {
		t.Fatal("expected error for adding to nonexistent secret")
	}
	if !errors.Is(err, core.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFakeStore_SecretExists(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"

	// Should not exist initially
	exists, err := store.SecretExists(ctx, secretResource)
	if err != nil {
		t.Fatalf("SecretExists failed: %v", err)
	}
	if exists {
		t.Error("secret should not exist initially")
	}

	// Create it
	_, _ = store.CreateSecret(ctx, secretResource, []byte("data"))

	// Should exist now
	exists, err = store.SecretExists(ctx, secretResource)
	if err != nil {
		t.Fatalf("SecretExists failed: %v", err)
	}
	if !exists {
		t.Error("secret should exist after creation")
	}
}

func TestFakeStore_SetVersion(t *testing.T) {
	store := NewFakeStore()
	ctx := context.Background()

	secretResource := "projects/test/secrets/my-secret"

	// SetVersion creates the secret and version directly
	store.SetVersion(secretResource, "5", []byte("version-5-data"))

	// Should be accessible
	data, err := store.AccessVersion(ctx, secretResource, "5")
	if err != nil {
		t.Fatalf("AccessVersion failed: %v", err)
	}
	if string(data) != "version-5-data" {
		t.Errorf("got %q, want %q", data, "version-5-data")
	}
}

func TestFakeStore_DataIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewFakeStore()

	secretResource := "projects/test/secrets/my-secret"
	original := []byte("original-value")
	_, _ = store.CreateSecret(ctx, secretResource, original)

	// Modify the original slice
	original[0] = 'X'

	// Stored value should be unchanged
	got, _ := store.AccessVersion(ctx, secretResource, "1")
	if string(got) != "original-value" {
		t.Error("stored value was mutated")
	}

	// Modify the returned slice
	got[0] = 'Y'

	// Re-fetch should still return original
	got2, _ := store.AccessVersion(ctx, secretResource, "1")
	if string(got2) != "original-value" {
		t.Error("returned value mutation affected store")
	}
}

func TestSecretResource(t *testing.T) {
	got := SecretResource("my-project", "my-secret")
	want := "projects/my-project/secrets/my-secret"
	if got != want {
		t.Errorf("SecretResource() = %q, want %q", got, want)
	}
}

func TestSecretVersionResource(t *testing.T) {
	got := SecretVersionResource("my-project", "my-secret", "3")
	want := "projects/my-project/secrets/my-secret/versions/3"
	if got != want {
		t.Errorf("SecretVersionResource() = %q, want %q", got, want)
	}
}
