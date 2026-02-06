package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestRetire_MarksSecretAsRetired(t *testing.T) {
	dir := t.TempDir()
	metadataDir := filepath.Join(dir, ".waxseal", "metadata")
	os.MkdirAll(metadataDir, 0o755)

	// Create active secret
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
      mode: static
`
	metadataPath := filepath.Join(metadataDir, "test-secret.yaml")
	if err := os.WriteFile(metadataPath, []byte(metadata), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Read and update to simulate retire
	data, _ := os.ReadFile(metadataPath)
	m, _ := core.ParseMetadata(data)

	// Verify initial state
	if m.IsRetired() {
		t.Error("secret should not be retired initially")
	}

	// Mark as retired
	m.Status = "retired"
	m.RetiredAt = "2026-02-02T00:00:00Z"
	m.RetireReason = "Test retirement"

	// Verify retired state
	if !m.IsRetired() {
		t.Error("secret should be retired after update")
	}
	if m.RetireReason != "Test retirement" {
		t.Errorf("RetireReason = %q, want %q", m.RetireReason, "Test retirement")
	}
}

func TestRetire_DeleteManifest(t *testing.T) {
	dir := t.TempDir()

	// Create metadata dir and apps dir
	metadataDir := filepath.Join(dir, ".waxseal", "metadata")
	appsDir := filepath.Join(dir, "apps", "test")
	os.MkdirAll(metadataDir, 0o755)
	os.MkdirAll(appsDir, 0o755)

	// Create manifest
	manifestPath := filepath.Join(appsDir, "sealed-secret.yaml")
	if err := os.WriteFile(manifestPath, []byte("kind: SealedSecret"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Verify manifest exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("manifest should exist")
	}

	// Simulate deletion
	if err := os.Remove(manifestPath); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	// Verify manifest deleted
	if _, err := os.Stat(manifestPath); err == nil {
		t.Error("manifest should be deleted")
	}
}

func TestRetire_ReplacedByField(t *testing.T) {
	m := &core.SecretMetadata{
		ShortName:  "old-secret",
		Status:     "retired",
		RetiredAt:  "2026-02-02T00:00:00Z",
		ReplacedBy: "new-secret",
	}

	if !m.IsRetired() {
		t.Error("should be retired")
	}
	if m.ReplacedBy != "new-secret" {
		t.Errorf("ReplacedBy = %q, want %q", m.ReplacedBy, "new-secret")
	}
}

func TestSerializeMetadata_IncludesRetirement(t *testing.T) {
	m := &core.SecretMetadata{
		ShortName:    "retired-secret",
		ManifestPath: "apps/test/sealed.yaml",
		SealedSecret: core.SealedSecretRef{
			Name:      "retired-secret",
			Namespace: "test",
			Scope:     "strict",
		},
		Status:       "retired",
		RetiredAt:    "2026-02-02T00:00:00Z",
		RetireReason: "No longer needed",
		ReplacedBy:   "new-secret",
		Keys: []core.KeyMetadata{
			{
				KeyName: "key",
				Source:  core.SourceConfig{Kind: "gsm"},
				GSM: &core.GSMRef{
					SecretResource: "projects/p/secrets/s",
					Version:        "1",
				},
				Rotation: &core.RotationConfig{Mode: "static"},
			},
		},
	}

	yaml := serializeMetadata(m)

	if !strings.Contains(yaml, "status: retired") {
		t.Error("YAML should contain 'status: retired'")
	}
	if !strings.Contains(yaml, "retiredAt:") {
		t.Error("YAML should contain 'retiredAt:'")
	}
	if !strings.Contains(yaml, "retireReason:") {
		t.Error("YAML should contain 'retireReason:'")
	}
	if !strings.Contains(yaml, "replacedBy:") {
		t.Error("YAML should contain 'replacedBy:'")
	}
}
