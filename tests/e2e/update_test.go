package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Update tests the `waxseal update` command
func TestE2E_Update(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantOutput []string
	}{
		{
			name:       "update errors on missing secret",
			args:       []string{"update", "nonexistent", "api_key", "--generate-random"},
			wantErr:    true,
			wantOutput: []string{"not found"},
		},
		{
			name:       "update errors on missing key",
			args:       []string{"update", "test-secret", "nonexistent_key", "--generate-random"},
			wantErr:    true,
			wantOutput: []string{"not found"},
		},
		{
			name:       "update errors on retired secret",
			args:       []string{"update", "retired-secret", "old_key", "--generate-random"},
			wantErr:    true,
			wantOutput: []string{"retired"},
		},
		{
			name:       "update dry run shows plan",
			args:       []string{"update", "test-secret", "api_key", "--generate-random", "--dry-run"},
			wantErr:    false,
			wantOutput: []string{"[DRY RUN]", "Create new version", "Update metadata"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := setupUpdateTest(t)
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
		})
	}
}

func setupUpdateTest(t *testing.T) string {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "waxseal-update-*")

	// Create config and directories
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)

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

	// Create cert
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	}

	// Create test secret metadata
	metadata := `shortName: test-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: api_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/test-api-key
      version: "1"
    rotation:
      mode: static
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/test-secret.yaml"), []byte(metadata), 0o644)

	// Create SealedSecret manifest
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    api_key: AgBYxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Create retired secret
	retiredMetadata := `shortName: retired-secret
manifestPath: apps/retired/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: default
  scope: strict
  type: Opaque
status: retired
retireReason: No longer needed
keys:
  - keyName: old_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/old-key
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/retired-secret.yaml"), []byte(retiredMetadata), 0o644)

	return tmpDir
}
