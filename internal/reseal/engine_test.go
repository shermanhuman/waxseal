package reseal

import (
	"context"
	"os"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

func TestEngine_EvaluateComputed(t *testing.T) {
	e := &Engine{}

	keyValues := map[string]string{
		"username": "admin",
		"password": "secret123",
	}

	config := &core.ComputedConfig{
		Kind:     "template",
		Template: "postgresql://{{user}}:{{pass}}@{{host}}:{{port}}/{{db}}",
		Inputs: []core.InputRef{
			{Var: "user", Ref: core.KeyRef{KeyName: "username"}},
			{Var: "pass", Ref: core.KeyRef{KeyName: "password"}},
		},
		Params: map[string]string{
			"host": "localhost",
			"port": "5432",
			"db":   "mydb",
		},
	}

	result, err := e.evaluateComputed(config, keyValues, nil)
	if err != nil {
		t.Fatalf("evaluateComputed failed: %v", err)
	}

	expected := "postgresql://admin:secret123@localhost:5432/mydb"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestEngine_ResealOne_WithFakeStore(t *testing.T) {
	ctx := context.Background()

	// Create temp directory with metadata
	dir := t.TempDir()

	// Create .waxseal/metadata directory
	metadataDir := dir + "/.waxseal/metadata"
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		t.Fatalf("create dir: %v", err)
	}

	// Create metadata file
	metadata := `shortName: test-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test-secret
  namespace: test
  scope: strict
status: active
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/password
      version: "1"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32
`
	if err := os.WriteFile(metadataDir+"/test-secret.yaml", []byte(metadata), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Create apps/test directory
	appsDir := dir + "/apps/test"
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		t.Fatalf("create apps dir: %v", err)
	}

	// Setup fake store with secret
	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/password", "1", []byte("supersecret"))

	// Setup fake sealer
	fakeSealer := seal.NewFakeSealer()

	// Create engine
	engine := NewEngine(fakeStore, fakeSealer, dir, false)

	// Reseal
	result, err := engine.ResealOne(ctx, "test-secret")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	if result.ShortName != "test-secret" {
		t.Errorf("shortName = %q, want %q", result.ShortName, "test-secret")
	}

	if result.KeysResealed != 1 {
		t.Errorf("keysResealed = %d, want %d", result.KeysResealed, 1)
	}

	// Verify manifest was written
	manifestPath := dir + "/apps/test/sealed-secret.yaml"
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	if !containsStr(string(content), "kind: SealedSecret") {
		t.Error("manifest should contain 'kind: SealedSecret'")
	}

	if !containsStr(string(content), "password:") {
		t.Error("manifest should contain 'password:' key")
	}
}

func TestEngine_DryRun(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	metadataDir := dir + "/.waxseal/metadata"
	_ = os.MkdirAll(metadataDir, 0o755)

	metadata := `shortName: dry-run-test
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test
  namespace: test
  scope: strict
status: active
keys:
  - keyName: secret
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/secret
      version: "1"
    rotation:
      mode: manual
`
	_ = os.WriteFile(metadataDir+"/dry-run-test.yaml", []byte(metadata), 0o644)

	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/secret", "1", []byte("value"))

	engine := NewEngine(fakeStore, seal.NewFakeSealer(), dir, true) // dry-run = true

	result, err := engine.ResealOne(ctx, "dry-run-test")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	if !result.DryRun {
		t.Error("expected DryRun=true")
	}

	// Manifest should NOT exist
	manifestPath := dir + "/apps/test/sealed-secret.yaml"
	_, err = os.ReadFile(manifestPath)
	if err == nil {
		t.Error("manifest should not exist in dry-run mode")
	}
}

func TestEngine_ComputedWithParams(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	metadataDir := dir + "/.waxseal/metadata"
	_ = os.MkdirAll(metadataDir, 0o755)
	_ = os.MkdirAll(dir+"/apps/test", 0o755)

	metadata := `shortName: db-secret
manifestPath: apps/test/db-sealed-secret.yaml
sealedSecret:
  name: db-secret
  namespace: test
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
      version: "1"
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
      template: "postgresql://{{user}}:{{pass}}@{{host}}/{{db}}"
      inputs:
        - var: user
          ref:
            keyName: username
        - var: pass
          ref:
            keyName: password
      params:
        host: "db.example.com"
        db: "myapp"
`
	_ = os.WriteFile(metadataDir+"/db-secret.yaml", []byte(metadata), 0o644)

	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/username", "1", []byte("admin"))
	fakeStore.SetVersion("projects/test/secrets/password", "1", []byte("secret123"))

	engine := NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)

	result, err := engine.ResealOne(ctx, "db-secret")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	if result.KeysResealed != 3 {
		t.Errorf("keysResealed = %d, want 3", result.KeysResealed)
	}

	// Verify manifest contains DATABASE_URL
	content, _ := os.ReadFile(dir + "/apps/test/db-sealed-secret.yaml")
	if !containsStr(string(content), "DATABASE_URL:") {
		t.Error("manifest should contain computed 'DATABASE_URL' key")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
