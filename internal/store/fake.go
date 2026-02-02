package store

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/shermanhuman/waxseal/internal/core"
)

// FakeStore is an in-memory implementation of Store for testing.
type FakeStore struct {
	mu      sync.RWMutex
	secrets map[string]*fakeSecret
}

type fakeSecret struct {
	versions map[string][]byte
	latest   int
}

// NewFakeStore creates a new in-memory fake store.
func NewFakeStore() *FakeStore {
	return &FakeStore{
		secrets: make(map[string]*fakeSecret),
	}
}

// AccessVersion retrieves a specific version of a secret.
func (f *FakeStore) AccessVersion(ctx context.Context, secretResource string, version string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	secret, ok := f.secrets[secretResource]
	if !ok {
		return nil, core.WrapNotFound(secretResource, nil)
	}

	data, ok := secret.versions[version]
	if !ok {
		return nil, core.WrapNotFound(fmt.Sprintf("%s/versions/%s", secretResource, version), nil)
	}

	// Return a copy to prevent mutation
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// AddVersion adds a new version to an existing secret.
func (f *FakeStore) AddVersion(ctx context.Context, secretResource string, data []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	secret, ok := f.secrets[secretResource]
	if !ok {
		return "", core.WrapNotFound(secretResource, nil)
	}

	secret.latest++
	version := strconv.Itoa(secret.latest)

	// Store a copy
	stored := make([]byte, len(data))
	copy(stored, data)
	secret.versions[version] = stored

	return version, nil
}

// CreateSecret creates a new secret with an initial version.
func (f *FakeStore) CreateSecret(ctx context.Context, secretResource string, data []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.secrets[secretResource]; ok {
		return "", fmt.Errorf("%s: %w", secretResource, core.ErrAlreadyExists)
	}

	// Store a copy
	stored := make([]byte, len(data))
	copy(stored, data)

	f.secrets[secretResource] = &fakeSecret{
		versions: map[string][]byte{"1": stored},
		latest:   1,
	}

	return "1", nil
}

// SecretExists checks if a secret exists.
func (f *FakeStore) SecretExists(ctx context.Context, secretResource string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	_, ok := f.secrets[secretResource]
	return ok, nil
}

// SetVersion sets a specific version for testing (bypasses normal versioning).
func (f *FakeStore) SetVersion(secretResource, version string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	secret, ok := f.secrets[secretResource]
	if !ok {
		secret = &fakeSecret{
			versions: make(map[string][]byte),
			latest:   0,
		}
		f.secrets[secretResource] = secret
	}

	// Store a copy
	stored := make([]byte, len(data))
	copy(stored, data)
	secret.versions[version] = stored

	// Update latest if this is a higher version
	if v, err := strconv.Atoi(version); err == nil && v > secret.latest {
		secret.latest = v
	}
}

// Clear removes all secrets from the store.
func (f *FakeStore) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = make(map[string]*fakeSecret)
}

// Compile-time check that FakeStore implements Store.
var _ Store = (*FakeStore)(nil)
