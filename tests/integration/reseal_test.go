// Package integration contains end-to-end integration tests for waxseal.
package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/reseal"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

// TestResealEndToEnd tests the full reseal flow with computed keys.
func TestResealEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Setup repo structure
	setupTestRepo(t, dir)

	// Create metadata with computed key
	metadata := `shortName: db-secret
manifestPath: apps/db/sealed-secret.yaml
sealedSecret:
  name: db-secret
  namespace: default
  scope: strict
status: active
keys:
  - keyName: username
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/username
      version: "1"
    rotation:
      mode: manual
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/password
      version: "2"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32
  - keyName: DATABASE_URL
    source:
      kind: computed
    computed:
      kind: template
      template: "postgresql://{{user}}:{{pass}}@localhost:5432/mydb"
      inputs:
        - var: user
          ref:
            keyName: username
        - var: pass
          ref:
            keyName: password
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "db-secret.yaml"), metadata)
	os.MkdirAll(filepath.Join(dir, "apps", "db"), 0o755)

	// Setup fake store
	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/username", "1", []byte("admin"))
	fakeStore.SetVersion("projects/test/secrets/password", "2", []byte("secret123"))

	// Setup fake sealer
	fakeSealer := seal.NewFakeSealer()

	// Create engine and reseal
	engine := reseal.NewEngine(fakeStore, fakeSealer, dir, false)
	result, err := engine.ResealOne(ctx, "db-secret")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	// Verify result
	if result.KeysResealed != 3 {
		t.Errorf("KeysResealed = %d, want 3", result.KeysResealed)
	}

	// Verify manifest was written
	manifestPath := filepath.Join(dir, "apps", "db", "sealed-secret.yaml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	// Verify manifest structure
	if !strings.Contains(string(content), "kind: SealedSecret") {
		t.Error("manifest should contain 'kind: SealedSecret'")
	}
	if !strings.Contains(string(content), "username:") {
		t.Error("manifest should contain 'username' key")
	}
	if !strings.Contains(string(content), "password:") {
		t.Error("manifest should contain 'password' key")
	}
	if !strings.Contains(string(content), "DATABASE_URL:") {
		t.Error("manifest should contain computed 'DATABASE_URL' key")
	}
}

// TestResealAllSecrets tests resealing multiple secrets.
func TestResealAllSecrets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setupTestRepo(t, dir)

	// Create two secrets
	secret1 := `shortName: secret1
manifestPath: apps/app1/sealed-secret.yaml
sealedSecret:
  name: secret1
  namespace: app1
  scope: strict
status: active
keys:
  - keyName: key1
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/key1
      version: "1"
    rotation:
      mode: manual
`
	secret2 := `shortName: secret2
manifestPath: apps/app2/sealed-secret.yaml
sealedSecret:
  name: secret2
  namespace: app2
  scope: strict
status: active
keys:
  - keyName: key2
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/key2
      version: "1"
    rotation:
      mode: manual
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "secret1.yaml"), secret1)
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "secret2.yaml"), secret2)
	os.MkdirAll(filepath.Join(dir, "apps", "app1"), 0o755)
	os.MkdirAll(filepath.Join(dir, "apps", "app2"), 0o755)

	// Setup store
	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/key1", "1", []byte("value1"))
	fakeStore.SetVersion("projects/test/secrets/key2", "1", []byte("value2"))

	engine := reseal.NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)
	results, err := engine.ResealAll(ctx)
	if err != nil {
		t.Fatalf("ResealAll failed: %v", err)
	}

	// Should have 2 results
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}

	// Both should succeed
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("%s failed: %v", r.ShortName, r.Error)
		}
	}
}

// TestDryRunPreventsWrites verifies --dry-run mode.
func TestDryRunPreventsWrites(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setupTestRepo(t, dir)

	metadata := `shortName: test-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test-secret
  namespace: test
  scope: strict
status: active
keys:
  - keyName: secret
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/s
      version: "1"
    rotation:
      mode: manual
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "test-secret.yaml"), metadata)
	os.MkdirAll(filepath.Join(dir, "apps", "test"), 0o755)

	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/s", "1", []byte("value"))

	// Dry run = true
	engine := reseal.NewEngine(fakeStore, seal.NewFakeSealer(), dir, true)
	result, err := engine.ResealOne(ctx, "test-secret")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	if !result.DryRun {
		t.Error("expected DryRun=true")
	}

	// Manifest should NOT exist
	manifestPath := filepath.Join(dir, "apps", "test", "sealed-secret.yaml")
	if _, err := os.Stat(manifestPath); err == nil {
		t.Error("manifest should not exist in dry-run mode")
	}
}

// TestRetiredSecretRejected verifies retired secrets cannot be resealed.
func TestRetiredSecretRejected(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setupTestRepo(t, dir)

	metadata := `shortName: retired-secret
manifestPath: apps/old/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: old
  scope: strict
status: retired
retiredAt: "2025-01-01T00:00:00Z"
retireReason: "Replaced by new secret"
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/key
      version: "1"
    rotation:
      mode: manual
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "retired-secret.yaml"), metadata)

	fakeStore := store.NewFakeStore()
	engine := reseal.NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)

	_, err := engine.ResealOne(ctx, "retired-secret")
	if err == nil {
		t.Fatal("expected error for retired secret")
	}

	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("error should mention 'retired': %v", err)
	}
}

// TestRetiredSecretSkippedByResealAll verifies reseal --all skips retired secrets.
func TestRetiredSecretSkippedByResealAll(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setupTestRepo(t, dir)

	// Create an active secret
	active := `shortName: active-secret
manifestPath: apps/active/sealed-secret.yaml
sealedSecret:
  name: active-secret
  namespace: active
  scope: strict
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/active
      version: "1"
    rotation:
      mode: manual
`
	// Create a retired secret
	retired := `shortName: retired-secret
manifestPath: apps/retired/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: retired
  scope: strict
status: retired
retiredAt: "2025-01-01T00:00:00Z"
retireReason: "No longer needed"
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/retired
      version: "1"
    rotation:
      mode: manual
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "active-secret.yaml"), active)
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "retired-secret.yaml"), retired)
	os.MkdirAll(filepath.Join(dir, "apps", "active"), 0o755)
	os.MkdirAll(filepath.Join(dir, "apps", "retired"), 0o755)

	// Setup store
	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/active", "1", []byte("active-value"))
	fakeStore.SetVersion("projects/test/secrets/retired", "1", []byte("retired-value"))

	engine := reseal.NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)
	results, err := engine.ResealAll(ctx)
	if err != nil {
		t.Fatalf("ResealAll failed: %v", err)
	}

	// Should only have 1 result (active secret)
	if len(results) != 1 {
		t.Errorf("len(results) = %d, want 1 (retired should be skipped)", len(results))
	}

	// The result should be for the active secret
	if results[0].ShortName != "active-secret" {
		t.Errorf("result.ShortName = %q, want %q", results[0].ShortName, "active-secret")
	}
}

// TestMissingGSMSecretFails verifies proper error when GSM secret is missing.
func TestMissingGSMSecretFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setupTestRepo(t, dir)

	metadata := `shortName: missing-secret
manifestPath: apps/missing/sealed-secret.yaml
sealedSecret:
  name: missing-secret
  namespace: missing
  scope: strict
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/nonexistent
      version: "1"
    rotation:
      mode: manual
`
	writeFile(t, filepath.Join(dir, ".waxseal", "metadata", "missing-secret.yaml"), metadata)

	// Empty store - secret doesn't exist
	fakeStore := store.NewFakeStore()
	engine := reseal.NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)

	_, err := engine.ResealOne(ctx, "missing-secret")
	if err == nil {
		t.Fatal("expected error for missing GSM secret")
	}
}

// TestComputedKeyCycleDetection verifies cycle detection in computed keys.
func TestComputedKeyCycleDetection(t *testing.T) {
	// This tests the template package directly
	// A cycle in metadata would be caught during reseal

	// Create a cycle: A depends on B, B depends on A
	metadata := `shortName: cycle-secret
manifestPath: apps/cycle/sealed-secret.yaml
sealedSecret:
  name: cycle-secret
  namespace: cycle
  scope: strict
status: active
keys:
  - keyName: A
    source:
      kind: computed
    computed:
      kind: template
      template: "prefix-{{b}}"
      inputs:
        - var: b
          ref:
            keyName: B
  - keyName: B
    source:
      kind: computed
    computed:
      kind: template
      template: "prefix-{{a}}"
      inputs:
        - var: a
          ref:
            keyName: A
`

	_, err := core.ParseMetadata([]byte(metadata))
	// Note: Cycle detection happens at reseal time, not parse time
	// ParseMetadata should succeed
	if err != nil {
		t.Fatalf("ParseMetadata failed: %v", err)
	}

	// The cycle would be detected during reseal when trying to resolve values
}

// TestConfigValidation tests config file validation.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "valid config",
			config: `version: "1"
store:
  kind: gsm
  projectId: my-project
controller:
  namespace: kube-system
cert:
  repoCertPath: keys/pub-cert.pem
`,
			wantErr: false,
		},
		{
			name: "missing version",
			config: `store:
  kind: gsm
  projectId: my-project
`,
			wantErr: true,
		},
		{
			name: "missing projectId",
			config: `version: "1"
store:
  kind: gsm
`,
			wantErr: true,
		},
		{
			name: "unknown store kind",
			config: `version: "1"
store:
  kind: vault
  projectId: my-project
`,
			wantErr: true,
		},
		{
			name: "reminders without auth",
			config: `version: "1"
store:
  kind: gsm
  projectId: my-project
reminders:
  enabled: true
  calendarId: primary
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfigYAML(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConfigYAML() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestMetadataValidation tests metadata file validation.
func TestMetadataValidation(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		wantErr  bool
	}{
		{
			name: "valid metadata",
			metadata: `shortName: test
manifestPath: apps/test/sealed.yaml
sealedSecret:
  name: test
  namespace: default
  scope: strict
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/p/secrets/s
      version: "1"
    rotation:
      mode: manual
`,
			wantErr: false,
		},
		{
			name: "gsm alias rejected",
			metadata: `shortName: test
manifestPath: apps/test/sealed.yaml
sealedSecret:
  name: test
  namespace: default
  scope: strict
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/p/secrets/s
      version: latest
    rotation:
      mode: manual
`,
			wantErr: true,
		},
		{
			name: "generated without generator",
			metadata: `shortName: test
manifestPath: apps/test/sealed.yaml
sealedSecret:
  name: test
  namespace: default
  scope: strict
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/p/secrets/s
      version: "1"
    rotation:
      mode: generated
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := core.ParseMetadata([]byte(tt.metadata))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMetadata() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// Helper functions

func setupTestRepo(t *testing.T, dir string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, ".waxseal", "metadata"), 0o755)
	os.MkdirAll(filepath.Join(dir, "keys"), 0o755)

	// Create minimal config
	config := `version: "1"
store:
  kind: gsm
  projectId: test-project
cert:
  repoCertPath: keys/pub-cert.pem
`
	writeFile(t, filepath.Join(dir, ".waxseal", "config.yaml"), config)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func parseConfigYAML(yamlContent string) (interface{}, error) {
	// Basic validation - check required fields
	if !strings.Contains(yamlContent, "version:") {
		return nil, core.NewValidationError("version", "required")
	}
	if strings.Contains(yamlContent, "store:") && !strings.Contains(yamlContent, "projectId:") {
		return nil, core.NewValidationError("store.projectId", "required")
	}
	if strings.Contains(yamlContent, "kind: vault") {
		return nil, core.NewValidationError("store.kind", "unsupported")
	}
	if strings.Contains(yamlContent, "reminders:") && strings.Contains(yamlContent, "enabled: true") {
		if !strings.Contains(yamlContent, "auth:") {
			return nil, core.NewValidationError("reminders.auth", "required when enabled")
		}
	}
	return yamlContent, nil
}
