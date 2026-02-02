// Package files provides safe file operations including atomic writes.
package files

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Validator is a function that validates content before writing.
// Return nil if valid, or an error describing the validation failure.
type Validator func(content []byte) error

// AtomicWriter provides atomic file write operations.
// Files are written to a temporary location first, then renamed.
type AtomicWriter struct {
	validators []Validator
}

// NewAtomicWriter creates a new AtomicWriter with optional validators.
func NewAtomicWriter(validators ...Validator) *AtomicWriter {
	return &AtomicWriter{validators: validators}
}

// Write atomically writes content to the target path.
// The operation either succeeds completely or makes no changes.
func (w *AtomicWriter) Write(path string, content []byte) error {
	// Validate before any file operations
	if err := w.validate(content); err != nil {
		return err
	}

	// Never write empty content
	if len(content) == 0 {
		return core.NewValidationError("content", "cannot write empty content")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	// Create temp file in same directory (for atomic rename)
	tmp, err := os.CreateTemp(dir, ".waxseal-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up temp file on any error
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	// Write content
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	// Sync to disk before rename
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	success = true
	return nil
}

// WriteFrom atomically writes content from a reader to the target path.
func (w *AtomicWriter) WriteFrom(path string, r io.Reader) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read content: %w", err)
	}
	return w.Write(path, content)
}

func (w *AtomicWriter) validate(content []byte) error {
	for _, v := range w.validators {
		if err := v(content); err != nil {
			return core.WrapValidation("content validation", err)
		}
	}
	return nil
}

// YAMLKindValidator returns a validator that checks for a specific YAML kind.
func YAMLKindValidator(expectedKind string) Validator {
	return func(content []byte) error {
		// Simple check: look for "kind: <expectedKind>" in content
		// A more robust implementation would parse the YAML
		kindPattern := []byte("kind: " + expectedKind)
		if !containsBytes(content, kindPattern) {
			return fmt.Errorf("expected kind: %s", expectedKind)
		}
		return nil
	}
}

// NonEmptyValidator returns a validator that rejects empty content.
func NonEmptyValidator() Validator {
	return func(content []byte) error {
		if len(content) == 0 {
			return fmt.Errorf("content is empty")
		}
		return nil
	}
}

func containsBytes(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
