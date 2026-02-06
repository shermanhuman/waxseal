package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Setup tests the `waxseal setup` command
func TestE2E_Setup(t *testing.T) {
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
			name:    "basic setup with project ID",
			args:    []string{"setup", "--project-id=test-project"},
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
			name:    "setup with custom controller namespace",
			args:    []string{"setup", "--project-id=test-project", "--controller-namespace=sealed-secrets"},
			wantErr: false,
			wantFiles: []string{
				".waxseal/config.yaml",
			},
			wantContent: map[string]string{
				".waxseal/config.yaml": "namespace: sealed-secrets",
			},
		},
		{
			name:    "setup with empty project ID",
			args:    []string{"setup", "--project-id="},
			wantErr: true,
		},
		{
			name:    "setup with skip-reminders flag",
			args:    []string{"setup", "--project-id=test-project", "--skip-reminders"},
			wantErr: false,
			wantFiles: []string{
				".waxseal/config.yaml",
				".waxseal/metadata",
			},
			wantContent: map[string]string{
				".waxseal/config.yaml": "projectId: test-project",
			},
		},
		{
			name:    "setup with custom controller name",
			args:    []string{"setup", "--project-id=test-project", "--controller-name=my-sealed-secrets", "--skip-reminders"},
			wantErr: false,
			wantFiles: []string{
				".waxseal/config.yaml",
			},
			wantContent: map[string]string{
				".waxseal/config.yaml": "serviceName: my-sealed-secrets",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create isolated temp directory for each test
			tmpDir, err := os.MkdirTemp("", "waxseal-setup-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Run waxseal setup
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

// TestE2E_SetupIdempotent tests that running setup twice doesn't break things
func TestE2E_SetupIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "waxseal-setup-idem-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// First setup
	_, err = runWaxsealWithDir(t, tmpDir, "setup", "--project-id=test-project", "--repo="+tmpDir)
	if err != nil {
		t.Fatalf("first setup: %v", err)
	}

	// Read config content
	configPath := filepath.Join(tmpDir, ".waxseal/config.yaml")
	config1, _ := os.ReadFile(configPath)

	// Second setup should fail or warn (config exists)
	output, err := runWaxsealWithDir(t, tmpDir, "setup", "--project-id=test-project", "--repo="+tmpDir)

	// Should either error or warn about existing config
	if err == nil && !strings.Contains(output, "already") && !strings.Contains(output, "exists") {
		// Check config wasn't corrupted
		config2, _ := os.ReadFile(configPath)
		if string(config1) != string(config2) {
			t.Error("config was modified on second setup")
		}
	}

	t.Log("✓ setup is safe to run multiple times")
}
