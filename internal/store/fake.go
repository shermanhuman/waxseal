package store

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/shermanhuman/waxseal/internal/core"
)

// FakeStore is an in-memory implementation of Store for testing.
type FakeStore struct {
	mu       sync.RWMutex
	secrets  map[string]*fakeSecret
	failures map[failureKey]error
}

type failureKey struct{ op, resource string }

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
// Validates that version is numeric to match GSMStore behavior.
func (f *FakeStore) AccessVersion(ctx context.Context, secretResource string, version string) ([]byte, error) {
	if err := f.failure("AccessVersion", secretResource); err != nil {
		return nil, err
	}

	// Validate numeric version (same as GSMStore)
	if err := ValidateNumericVersion(version); err != nil {
		return nil, err
	}

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
	if err := f.failure("AddVersion", secretResource); err != nil {
		return "", err
	}

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
	if err := f.failure("CreateSecret", secretResource); err != nil {
		return "", err
	}

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

// DeleteSecret permanently deletes a secret.
func (f *FakeStore) DeleteSecret(ctx context.Context, secretResource string) error {
	if err := f.failure("DeleteSecret", secretResource); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.secrets[secretResource]; !ok {
		return core.WrapNotFound(secretResource, nil)
	}

	delete(f.secrets, secretResource)
	return nil
}

// EnsureVersion adds a version, creating the secret first when needed.
func (f *FakeStore) EnsureVersion(ctx context.Context, secretResource string, data []byte) (string, bool, error) {
	version, err := f.AddVersion(ctx, secretResource, data)
	if err == nil {
		return version, false, nil
	}
	if !core.IsNotFound(err) {
		return "", false, err
	}
	version, err = f.CreateSecret(ctx, secretResource, data)
	if err != nil {
		return "", false, err
	}
	return version, true, nil
}

// VersionExists reports whether the numeric version exists.
func (f *FakeStore) VersionExists(ctx context.Context, secretResource string, version string) (bool, error) {
	_, err := f.AccessVersion(ctx, secretResource, version)
	if core.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
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

// FailOn makes op ("AccessVersion", "AddVersion", "CreateSecret",
// "DeleteSecret") return err for secretResource, or for every
// resource when secretResource is empty. Tests use it to exercise rollback.
func (f *FakeStore) FailOn(op, secretResource string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures == nil {
		f.failures = make(map[failureKey]error)
	}
	f.failures[failureKey{op, secretResource}] = err
}

func (f *FakeStore) failure(op, secretResource string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if err, ok := f.failures[failureKey{op, secretResource}]; ok {
		return err
	}
	return f.failures[failureKey{op, ""}]
}

// Resources returns the sorted resource names of all secrets in the store.
func (f *FakeStore) Resources() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	names := make([]string, 0, len(f.secrets))
	for name := range f.secrets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Clear removes all secrets from the store.
func (f *FakeStore) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = make(map[string]*fakeSecret)
}

// Compile-time check that FakeStore implements Store.
var _ Store = (*FakeStore)(nil)
