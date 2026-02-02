package core

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"NotFound", WrapNotFound("secret/foo", nil), ErrNotFound},
		{"NotFoundWithCause", WrapNotFound("secret/foo", errors.New("underlying")), ErrNotFound},
		{"PermissionDenied", WrapPermissionDenied("secret/foo", nil), ErrPermissionDenied},
		{"Validation", WrapValidation("config", nil), ErrValidation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("expected %v to match %v", tt.err, tt.sentinel)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := NewValidationError("version", "must be numeric")

	// Should match ErrValidation
	if !errors.Is(err, ErrValidation) {
		t.Error("ValidationError should match ErrValidation")
	}

	// Should have useful message
	expected := "version: must be numeric"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestValidationErrorNoField(t *testing.T) {
	err := NewValidationError("", "config is invalid")

	if err.Error() != "config is invalid" {
		t.Errorf("got %q, want %q", err.Error(), "config is invalid")
	}
}
