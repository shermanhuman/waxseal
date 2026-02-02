// Package store defines the secret store interface and implementations.
package store

import (
	"context"
)

// Store is the interface for secret storage backends.
// Implementations include GSM (Google Secret Manager) and in-memory fakes for testing.
type Store interface {
	// AccessVersion retrieves a specific version of a secret.
	// Returns the secret value as bytes.
	// Returns ErrNotFound if the secret or version doesn't exist.
	// Returns ErrPermissionDenied if access is denied.
	AccessVersion(ctx context.Context, secretResource string, version string) ([]byte, error)

	// AddVersion adds a new version to an existing secret.
	// Returns the new version number as a string.
	// Returns ErrNotFound if the secret doesn't exist.
	AddVersion(ctx context.Context, secretResource string, data []byte) (string, error)

	// CreateSecret creates a new secret with an initial version.
	// Returns the version number of the initial version (typically "1").
	// Returns ErrAlreadyExists if the secret already exists.
	CreateSecret(ctx context.Context, secretResource string, data []byte) (string, error)

	// SecretExists checks if a secret exists.
	SecretExists(ctx context.Context, secretResource string) (bool, error)
}

// SecretResource constructs a GSM secret resource path.
// Format: projects/<project>/secrets/<secretId>
func SecretResource(project, secretID string) string {
	return "projects/" + project + "/secrets/" + secretID
}

// SecretVersionResource constructs a GSM secret version resource path.
// Format: projects/<project>/secrets/<secretId>/versions/<version>
func SecretVersionResource(project, secretID, version string) string {
	return SecretResource(project, secretID) + "/versions/" + version
}
