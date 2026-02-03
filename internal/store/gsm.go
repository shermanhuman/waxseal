package store

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/shermanhuman/waxseal/internal/core"
)

// GSMStore implements Store using Google Secret Manager.
type GSMStore struct {
	client    *secretmanager.Client
	projectID string
}

// NewGSMStore creates a new GSM store.
// Uses Application Default Credentials (ADC) for authentication.
func NewGSMStore(ctx context.Context, projectID string) (*GSMStore, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create secret manager client: %w", err)
	}

	return &GSMStore{
		client:    client,
		projectID: projectID,
	}, nil
}

// Close closes the underlying client.
func (g *GSMStore) Close() error {
	return g.client.Close()
}

// numericVersionPattern validates that a version is purely numeric.
var numericVersionPattern = regexp.MustCompile(`^[0-9]+$`)

// AccessVersion retrieves a specific version of a secret.
func (g *GSMStore) AccessVersion(ctx context.Context, secretResource string, version string) ([]byte, error) {
	// Validate version is numeric (no aliases allowed)
	if !numericVersionPattern.MatchString(version) {
		return nil, core.NewValidationError("version", "must be numeric (aliases like 'latest' are not supported)")
	}

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretResource + "/versions/" + version,
	}

	result, err := g.client.AccessSecretVersion(ctx, req)
	if err != nil {
		// Check for common error types
		errStr := err.Error()
		if contains(errStr, "NotFound") || contains(errStr, "not found") {
			return nil, core.WrapNotFound(secretResource+"/versions/"+version, err)
		}
		if contains(errStr, "PermissionDenied") || contains(errStr, "permission denied") {
			return nil, core.WrapPermissionDenied(secretResource, err)
		}
		return nil, fmt.Errorf("access secret version: %w", err)
	}

	return result.Payload.Data, nil
}

// AddVersion adds a new version to an existing secret.
func (g *GSMStore) AddVersion(ctx context.Context, secretResource string, data []byte) (string, error) {
	req := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretResource,
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	}

	result, err := g.client.AddSecretVersion(ctx, req)
	if err != nil {
		errStr := err.Error()
		if contains(errStr, "NotFound") || contains(errStr, "not found") {
			return "", core.WrapNotFound(secretResource, err)
		}
		if contains(errStr, "PermissionDenied") || contains(errStr, "permission denied") {
			return "", core.WrapPermissionDenied(secretResource, err)
		}
		return "", fmt.Errorf("add secret version: %w", err)
	}

	// Extract version number from the full resource name
	// Format: projects/.../secrets/.../versions/<version>
	version := extractVersionFromName(result.Name)
	return version, nil
}

// CreateSecret creates a new secret with an initial version.
func (g *GSMStore) CreateSecret(ctx context.Context, secretResource string, data []byte) (string, error) {
	// Extract secret ID from resource path
	secretID := extractSecretIDFromResource(secretResource)
	if secretID == "" {
		return "", core.NewValidationError("secretResource", "invalid format")
	}

	// Create the secret
	createReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   "projects/" + g.projectID,
		SecretId: secretID,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	_, err := g.client.CreateSecret(ctx, createReq)
	if err != nil {
		errStr := err.Error()
		if contains(errStr, "AlreadyExists") || contains(errStr, "already exists") {
			return "", fmt.Errorf("%s: %w", secretResource, core.ErrAlreadyExists)
		}
		if contains(errStr, "PermissionDenied") || contains(errStr, "permission denied") {
			return "", core.WrapPermissionDenied(secretResource, err)
		}
		return "", fmt.Errorf("create secret: %w", err)
	}

	// Add the initial version
	return g.AddVersion(ctx, secretResource, data)
}

// CreateSecretVersion creates a secret if it doesn't exist and adds a version.
// This is an idempotent operation for bootstrapping secrets.
func (g *GSMStore) CreateSecretVersion(ctx context.Context, secretResource string, data []byte) (string, error) {
	// Try to add a version first (secret may already exist)
	version, err := g.AddVersion(ctx, secretResource, data)
	if err == nil {
		return version, nil
	}

	// If secret doesn't exist, create it
	if core.IsNotFound(err) {
		return g.CreateSecret(ctx, secretResource, data)
	}

	return "", err
}

// SecretExists checks if a secret exists.
func (g *GSMStore) SecretExists(ctx context.Context, secretResource string) (bool, error) {
	req := &secretmanagerpb.GetSecretRequest{
		Name: secretResource,
	}

	_, err := g.client.GetSecret(ctx, req)
	if err != nil {
		errStr := err.Error()
		if contains(errStr, "NotFound") || contains(errStr, "not found") {
			return false, nil
		}
		return false, fmt.Errorf("get secret: %w", err)
	}

	return true, nil
}

// extractVersionFromName extracts the version number from a full version resource name.
func extractVersionFromName(name string) string {
	// name format: projects/.../secrets/.../versions/<version>
	re := regexp.MustCompile(`/versions/(\d+)$`)
	matches := re.FindStringSubmatch(name)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

// extractSecretIDFromResource extracts the secret ID from a resource path.
func extractSecretIDFromResource(resource string) string {
	// resource format: projects/<project>/secrets/<secretId>
	re := regexp.MustCompile(`^projects/[^/]+/secrets/([^/]+)$`)
	matches := re.FindStringSubmatch(resource)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Validate version is numeric for external callers
func ValidateNumericVersion(version string) error {
	if !numericVersionPattern.MatchString(version) {
		return core.NewValidationError("version", "must be numeric (aliases like 'latest' are not supported)")
	}
	if _, err := strconv.Atoi(version); err != nil {
		return core.NewValidationError("version", "must be a valid integer")
	}
	return nil
}

// Compile-time check that GSMStore implements Store.
var _ Store = (*GSMStore)(nil)
