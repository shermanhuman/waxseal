package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Init tests the `waxseal init` command
func TestE2E_Init(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		wantFiles   []string
		wantContent map[string]string
	}{
		{
			name:    "basic init with project ID",
			args:    []string{"init", "--project-id=test-project", "--non-interactive"},
			wantErr: false,
			wantFiles: []string{
				".waxseal/config.yaml",
				".waxseal/metadata",
				"keys/pub-cert.pem",
			},
			wantContent: map[string]string{
				".waxseal/config.yaml": "projectId: test-project",
			},
		},
		{
			name:    "init with custom controller namespace",
			args:    []string{"init", "--project-id=test-project", "--controller-namespace=sealed-secrets", "--non-interactive"},
			wantErr: false,
			wantFiles: []string{
				".waxseal/config.yaml",
			},
			wantContent: map[string]string{
				".waxseal/config.yaml": "namespace: sealed-secrets",
			},
		},
		{
			name:    "init without required project ID",
			args:    []string{"init", "--non-interactive"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create isolated temp directory for each test
			tmpDir, err := os.MkdirTemp("", "waxseal-init-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Run waxseal init
			args := append(tt.args, "--repo="+tmpDir)
			output, err := runWaxsealWithDir(t, tmpDir, args...)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none. Output: %s", output)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v\nOutput: %s", err, output)
			}

			// Verify expected files exist
			for _, f := range tt.wantFiles {
				path := filepath.Join(tmpDir, f)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected file %s to exist", f)
				}
			}

			// Verify expected content
			for file, content := range tt.wantContent {
				path := filepath.Join(tmpDir, file)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("read %s: %v", file, err)
					continue
				}
				if !strings.Contains(string(data), content) {
					t.Errorf("file %s should contain %q, got: %s", file, content, string(data))
				}
			}

			t.Logf("✓ %s", tt.name)
		})
	}
}

// TestE2E_InitIdempotent tests that running init twice doesn't break things
func TestE2E_InitIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "waxseal-init-idem-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// First init
	_, err = runWaxsealWithDir(t, tmpDir, "init", "--project-id=test-project", "--non-interactive", "--repo="+tmpDir)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}

	// Read config content
	configPath := filepath.Join(tmpDir, ".waxseal/config.yaml")
	config1, _ := os.ReadFile(configPath)

	// Second init should fail or warn (config exists)
	output, err := runWaxsealWithDir(t, tmpDir, "init", "--project-id=test-project", "--non-interactive", "--repo="+tmpDir)

	// Should either error or warn about existing config
	if err == nil && !strings.Contains(output, "already") && !strings.Contains(output, "exists") {
		// Check config wasn't corrupted
		config2, _ := os.ReadFile(configPath)
		if string(config1) != string(config2) {
			t.Error("config was modified on second init")
		}
	}

	t.Log("✓ init is safe to run multiple times")
}
