package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Show tests the `waxseal show` command
func TestE2E_Show(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tests := []struct {
		name       string
		setupFunc  func(t *testing.T) string
		args       []string
		wantErr    bool
		wantOutput []string
	}{
		{
			name:      "show displays metadata",
			setupFunc: setupShowTest,
			args:      []string{"show", "test-secret"},
			wantErr:   false,
			wantOutput: []string{
				"test-secret",
				"default",
				"api_key",
			},
		},
		{
			name:      "show with JSON output",
			setupFunc: setupShowTest,
			args:      []string{"show", "test-secret", "--json"},
			wantErr:   false,
			wantOutput: []string{
				`"shortName": "test-secret"`,
				`"namespace": "default"`,
				`"keyName": "api_key"`,
			},
		},
		{
			name:      "show with YAML output",
			setupFunc: setupShowTest,
			args:      []string{"show", "test-secret", "--yaml"},
			wantErr:   false,
			wantOutput: []string{
				"shortName: test-secret",
				"namespace: default",
				"keyName: api_key",
			},
		},
		{
			name: "show errors on missing secret",
			setupFunc: func(t *testing.T) string {
				t.Helper()
				tmpDir, _ := os.MkdirTemp("", "waxseal-show-*")
				os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
				return tmpDir
			},
			args:       []string{"show", "nonexistent"},
			wantErr:    true,
			wantOutput: []string{"not found"},
		},
		{
			name:      "show displays retired status",
			setupFunc: setupRetiredShowTest,
			args:      []string{"show", "retired-secret"},
			wantErr:   false,
			wantOutput: []string{
				"retired",
				"Retired:",
				"No longer needed",
			},
		},
		{
			name:      "show displays multiple keys",
			setupFunc: setupMultiKeyShowTest,
			args:      []string{"show", "multi-key-secret"},
			wantErr:   false,
			wantOutput: []string{
				"api_key",
				"db_password",
				"jwt_secret",
				"Keys (3)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := tt.setupFunc(t)
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

func setupShowTest(t *testing.T) string {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "waxseal-show-*")
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)

	// Write test metadata
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
      secretResource: projects/test-project/secrets/api-key
      version: "1"
    rotation:
      mode: static
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/test-secret.yaml"), []byte(metadata), 0o644)

	return tmpDir
}

func setupRetiredShowTest(t *testing.T) string {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "waxseal-show-retired-*")
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)

	metadata := `shortName: retired-secret
manifestPath: apps/old/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: default
  scope: strict
  type: Opaque
status: retired
retireReason: No longer needed
replacedBy: new-secret
keys:
  - keyName: old_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/old-key
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/retired-secret.yaml"), []byte(metadata), 0o644)

	return tmpDir
}

func setupMultiKeyShowTest(t *testing.T) string {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "waxseal-show-multi-*")
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)

	metadata := `shortName: multi-key-secret
manifestPath: apps/multi/sealed-secret.yaml
sealedSecret:
  name: multi-key-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: api_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/api-key
      version: "1"
  - keyName: db_password
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/db-password
      version: "2"
  - keyName: jwt_secret
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/jwt-secret
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/multi-key-secret.yaml"), []byte(metadata), 0o644)

	return tmpDir
}
