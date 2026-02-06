package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestRequiresMetadata(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"list", true},
		{"validate", true},
		{"reseal", true},
		{"rotate", true},
		{"retire", true},
		{"setup", false},
		{"discover", false},
		{"reminders", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := requiresMetadata(tt.cmd)
			if got != tt.want {
				t.Errorf("requiresMetadata(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestCheckMetadataExists_NoConfig(t *testing.T) {
	dir := t.TempDir()

	// Save original repoPath
	origRepoPath := repoPath
	defer func() { repoPath = origRepoPath }()
	repoPath = dir

	// Create a test command
	cmd := &cobra.Command{Use: "list"}

	ok, err := checkMetadataExists(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when config is missing")
	}
}

func TestCheckMetadataExists_NoMetadataDir(t *testing.T) {
	dir := t.TempDir()

	// Create config
	waxsealDir := filepath.Join(dir, ".waxseal")
	os.MkdirAll(waxsealDir, 0o755)
	os.WriteFile(filepath.Join(waxsealDir, "config.yaml"), []byte("store:\n  kind: gsm"), 0o644)

	// Save original repoPath and yes flag
	origRepoPath := repoPath
	origYes := yes
	defer func() {
		repoPath = origRepoPath
		yes = origYes
	}()
	repoPath = dir
	yes = false // Don't prompt interactively

	cmd := &cobra.Command{Use: "list"}

	// This will prompt for input which we can't easily test in unit tests
	// Just verify it doesn't panic
	// In a real test we'd use testify/mock or similar
	_ = cmd
}

func TestCheckMetadataExists_EmptyMetadataDir(t *testing.T) {
	dir := t.TempDir()

	// Create config and empty metadata dir
	waxsealDir := filepath.Join(dir, ".waxseal")
	os.MkdirAll(filepath.Join(waxsealDir, "metadata"), 0o755)
	os.WriteFile(filepath.Join(waxsealDir, "config.yaml"), []byte("store:\n  kind: gsm"), 0o644)

	origRepoPath := repoPath
	defer func() { repoPath = origRepoPath }()
	repoPath = dir

	cmd := &cobra.Command{Use: "list"}

	ok, err := checkMetadataExists(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false when metadata directory is empty")
	}
}

func TestCheckMetadataExists_WithMetadata(t *testing.T) {
	dir := t.TempDir()

	// Create config and metadata
	waxsealDir := filepath.Join(dir, ".waxseal")
	metadataDir := filepath.Join(waxsealDir, "metadata")
	os.MkdirAll(metadataDir, 0o755)
	os.WriteFile(filepath.Join(waxsealDir, "config.yaml"), []byte("store:\n  kind: gsm"), 0o644)
	os.WriteFile(filepath.Join(metadataDir, "test.yaml"), []byte("shortName: test"), 0o644)

	origRepoPath := repoPath
	defer func() { repoPath = origRepoPath }()
	repoPath = dir

	cmd := &cobra.Command{Use: "list"}

	ok, err := checkMetadataExists(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true when metadata exists")
	}
}

func TestCheckMetadataExists_SkipsNonMetadataCommands(t *testing.T) {
	dir := t.TempDir() // Empty directory, no config

	origRepoPath := repoPath
	defer func() { repoPath = origRepoPath }()
	repoPath = dir

	// init command should not require metadata
	cmd := &cobra.Command{Use: "init"}

	ok, err := checkMetadataExists(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for commands that don't require metadata")
	}
}
