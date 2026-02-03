package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil state")
	}
	if len(s.Rotations) != 0 {
		t.Errorf("expected empty rotations, got %d", len(s.Rotations))
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()

	// Create .waxseal dir
	waxsealDir := filepath.Join(dir, ".waxseal")
	if err := os.MkdirAll(waxsealDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create and save state
	s := &State{
		LastCertFingerprint: "abc123",
	}
	s.AddRotation("my-secret", "password", "rotate", "2")
	s.AddRetirement("old-secret", "deprecated", "new-secret")

	if err := s.Save(dir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load and verify
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.LastCertFingerprint != "abc123" {
		t.Errorf("fingerprint mismatch: got %q", loaded.LastCertFingerprint)
	}
	if len(loaded.Rotations) != 1 {
		t.Errorf("expected 1 rotation, got %d", len(loaded.Rotations))
	}
	if len(loaded.Retirements) != 1 {
		t.Errorf("expected 1 retirement, got %d", len(loaded.Retirements))
	}
	if loaded.Rotations[0].ShortName != "my-secret" {
		t.Errorf("rotation shortName mismatch: got %q", loaded.Rotations[0].ShortName)
	}
	if loaded.Retirements[0].ReplacedBy != "new-secret" {
		t.Errorf("retirement replacedBy mismatch: got %q", loaded.Retirements[0].ReplacedBy)
	}
}

func TestAddRotation_KeepsMax100(t *testing.T) {
	s := &State{}

	// Add 110 rotations
	for i := 0; i < 110; i++ {
		s.AddRotation("secret", "", "reseal", "")
	}

	if len(s.Rotations) != 100 {
		t.Errorf("expected 100 rotations, got %d", len(s.Rotations))
	}
}

func TestUpdateCertFingerprint(t *testing.T) {
	s := &State{}
	s.UpdateCertFingerprint("new-fingerprint-123")

	if s.LastCertFingerprint != "new-fingerprint-123" {
		t.Errorf("fingerprint not updated: got %q", s.LastCertFingerprint)
	}
}
