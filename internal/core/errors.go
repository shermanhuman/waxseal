// Package core defines domain types and interfaces for waxseal.
package core

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure cases.
// These can be checked with errors.Is().
var (
	// ErrNotFound indicates a resource (secret, version, file) was not found.
	ErrNotFound = errors.New("not found")

	// ErrPermissionDenied indicates the caller lacks permission for the operation.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrValidation indicates input failed validation.
	ErrValidation = errors.New("validation failed")

	// ErrCycle indicates a circular dependency was detected (e.g., computed keys).
	ErrCycle = errors.New("cycle detected")

	// ErrAlreadyExists indicates default resource already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrRetired indicates an operation was attempted on a retired secret.
	ErrRetired = errors.New("secret is retired")

	// ErrUnauthenticated indicates the caller's credentials are missing or expired.
	ErrUnauthenticated = errors.New("unauthenticated")
)

// WrapNotFound wraps an error with ErrNotFound context.
func WrapNotFound(resource string, err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", resource, ErrNotFound)
	}
	return fmt.Errorf("%s: %w: %v", resource, ErrNotFound, err)
}

// WrapPermissionDenied wraps an error with ErrPermissionDenied context.
func WrapPermissionDenied(resource string, err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", resource, ErrPermissionDenied)
	}
	return fmt.Errorf("%s: %w: %v", resource, ErrPermissionDenied, err)
}

// WrapValidation wraps an error with ErrValidation context.
func WrapValidation(context string, err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", context, ErrValidation)
	}
	return fmt.Errorf("%s: %w: %v", context, ErrValidation, err)
}

// ValidationError provides structured validation failure information.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// Is allows ValidationError to match ErrValidation.
func (e ValidationError) Is(target error) bool {
	return target == ErrValidation
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field, message string) error {
	return ValidationError{Field: field, Message: message}
}

// IsNotFound checks if an error is a not found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsPermissionDenied checks if an error is a permission denied error.
func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// IsAlreadyExists checks if an error is an already exists error.
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

// WrapUnauthenticated wraps an error with ErrUnauthenticated context.
func WrapUnauthenticated(resource string, err error) error {
	hint := "run 'gcloud auth application-default login' to re-authenticate"
	if err == nil {
		return fmt.Errorf("%s: %w — %s", resource, ErrUnauthenticated, hint)
	}
	return fmt.Errorf("%s: %w — %s: %v", resource, ErrUnauthenticated, hint, err)
}

// IsUnauthenticated checks if an error is an unauthenticated error.
func IsUnauthenticated(err error) bool {
	return errors.Is(err, ErrUnauthenticated)
}
