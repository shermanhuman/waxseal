package files

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestAtomicWriter_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	w := NewAtomicWriter()
	content := []byte("key: value\n")

	if err := w.Write(path, content); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify content
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestAtomicWriter_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.yaml")

	w := NewAtomicWriter()
	content := []byte("key: value\n")

	if err := w.Write(path, content); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file was not created")
	}
}

func TestAtomicWriter_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	w := NewAtomicWriter()

	err := w.Write(path, []byte{})
	if err == nil {
		t.Fatal("expected error for empty content")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}

	// File should not exist
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should not exist after validation failure")
	}
}

func TestAtomicWriter_ValidationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	validator := func(content []byte) error {
		return errors.New("validation failed")
	}

	w := NewAtomicWriter(validator)
	content := []byte("key: value\n")

	err := w.Write(path, content)
	if err == nil {
		t.Fatal("expected validation error")
	}

	// File should not exist
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should not exist after validation failure")
	}
}

func TestAtomicWriter_NoTempFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	validator := func(content []byte) error {
		return errors.New("fail")
	}

	w := NewAtomicWriter(validator)
	_ = w.Write(path, []byte("content"))

	// Check no temp files left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestAtomicWriter_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	w := NewAtomicWriter()

	// Write initial content
	if err := w.Write(path, []byte("old content")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Overwrite
	if err := w.Write(path, []byte("new content")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new content" {
		t.Errorf("got %q, want %q", got, "new content")
	}
}

func TestYAMLKindValidator(t *testing.T) {
	validator := YAMLKindValidator("SealedSecret")

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "valid",
			content: "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: foo",
			wantErr: false,
		},
		{
			name:    "wrong kind",
			content: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: foo",
			wantErr: true,
		},
		{
			name:    "no kind",
			content: "foo: bar",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator([]byte(tt.content))
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
