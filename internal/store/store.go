// Package store defines the secret store interface and implementations.
package store

import (
	"context"
	"strings"
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

	// CreateSecretVersion creates a secret if needed and adds a version.
	// This is an idempotent operation - it won't fail if secret already exists.
	// Useful for bootstrapping where you want to ensure data is stored.
	CreateSecretVersion(ctx context.Context, secretResource string, data []byte) (string, error)

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

// SanitizeGSMName converts a key name to a valid GSM secret name component.
// GSM allows: letters, numbers, hyphens, underscores.
// Other characters are replaced with hyphens; leading/trailing hyphens are trimmed.
func SanitizeGSMName(name string) string {
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	return strings.Trim(result, "-")
}

// FormatSecretID builds a conventional GSM secret ID from a short name and key name.
// The key name is sanitized for GSM compatibility.
func FormatSecretID(shortName, keyName string) string {
	return shortName + "-" + SanitizeGSMName(keyName)
}
