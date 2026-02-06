package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Add tests the `waxseal add` command
func TestE2E_Add(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantOutput []string
		checkFiles []string // files that should exist after
	}{
		{
			name:       "add requires namespace when using --key",
			args:       []string{"add", "test-secret", "--key=api_key:random"},
			wantErr:    true,
			wantOutput: []string{"--namespace is required"},
		},
		{
			name:       "add dry run shows plan",
			args:       []string{"add", "test-secret", "--namespace=default", "--key=api_key:random", "--dry-run"},
			wantErr:    false,
			wantOutput: []string{"[DRY RUN]", "test-secret", "default", "api_key"},
		},
		{
			name:       "add fails if secret exists",
			args:       []string{"add", "existing-secret", "--namespace=default", "--key=api_key:random"},
			wantErr:    true,
			wantOutput: []string{"already exists"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := setupAddTest(t, tt.name)
			defer os.RemoveAll(tmpDir)

			output, err := runWaxsealWithDir(t, tmpDir, append(tt.args, "--repo="+tmpDir)...)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v\nOutput: %s", err, output)
				}
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot: %s", want, output)
				}
			}

			for _, f := range tt.checkFiles {
				path := filepath.Join(tmpDir, f)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected file %q to exist", f)
				}
			}
		})
	}
}

func setupAddTest(t *testing.T, testName string) string {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "waxseal-add-*")

	// Create config
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)

	config := `version: "1"
store:
  kind: gsm
  projectId: test-project
controller:
  namespace: kube-system
  serviceName: sealed-secrets
cert:
  repoCertPath: keys/pub-cert.pem
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/config.yaml"), []byte(config), 0o644)

	// Create a test cert (we need a real cert for sealing)
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	}

	// For "add fails if secret exists" test, create existing secret
	if strings.Contains(testName, "exists") {
		existingMetadata := `shortName: existing-secret
manifestPath: apps/existing/sealed-secret.yaml
sealedSecret:
  name: existing-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: old_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/old-key
      version: "1"
`
		os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/existing-secret.yaml"), []byte(existingMetadata), 0o644)
	}

	return tmpDir
}

// TestE2E_AddDryRun tests that dry run doesn't create files
func TestE2E_AddDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupAddTest(t, "dry-run")
	defer os.RemoveAll(tmpDir)

	// Run add with dry-run
	output, err := runWaxsealWithDir(t, tmpDir,
		"add", "new-secret",
		"--namespace=default",
		"--key=api_key:random",
		"--dry-run",
		"--repo="+tmpDir,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v\nOutput: %s", err, output)
	}

	// Check that no files were created
	metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/new-secret.yaml")
	if _, err := os.Stat(metadataPath); !os.IsNotExist(err) {
		t.Error("dry run should not create metadata file")
	}

	manifestPath := filepath.Join(tmpDir, "apps/new-secret/sealed-secret.yaml")
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Error("dry run should not create manifest file")
	}

	t.Log("✓ dry run creates no files")
}
