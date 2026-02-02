package reseal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

// TestGolden_OpaqueSecret tests output for a simple Opaque secret.
func TestGolden_OpaqueSecret(t *testing.T) {
	runGoldenTest(t, "opaque", map[string]map[string]string{
		"projects/test/secrets/password": {"1": "password-value"},
		"projects/test/secrets/api-key":  {"2": "api-key-value"},
		"projects/test/secrets/username": {"1": "user-value"},
	})
}

// TestGolden_DockerSecret tests output for a dockerconfigjson secret.
func TestGolden_DockerSecret(t *testing.T) {
	runGoldenTest(t, "docker", map[string]map[string]string{
		"projects/test/secrets/docker-config": {"1": "docker-config-value"},
	})
}

// TestGolden_ComputedSecret tests output for a secret with computed keys.
func TestGolden_ComputedSecret(t *testing.T) {
	runGoldenTest(t, "computed", map[string]map[string]string{
		"projects/test/secrets/db-user": {"1": "admin"},
		"projects/test/secrets/db-pass": {"1": "secret123"},
	})
}

func runGoldenTest(t *testing.T, name string, secrets map[string]map[string]string) {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	// Setup directory structure
	metadataDir := filepath.Join(dir, ".waxseal", "metadata")
	os.MkdirAll(metadataDir, 0o755)
	os.MkdirAll(filepath.Join(dir, "apps", "golden"), 0o755)

	// Read golden input
	goldenDir := filepath.Join("..", "..", "testdata", "golden")
	inputPath := filepath.Join(goldenDir, "input_"+name+".yaml")
	expectedPath := filepath.Join(goldenDir, "expected_"+name+".yaml")

	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}

	expectedData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	// Parse metadata to get manifest path
	metadata, err := core.ParseMetadata(inputData)
	if err != nil {
		t.Fatalf("parse metadata: %v", err)
	}

	// Write input to temp dir
	metadataPath := filepath.Join(metadataDir, "golden-"+name+".yaml")
	if err := os.WriteFile(metadataPath, inputData, 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Setup fake store
	fakeStore := store.NewFakeStore()
	for secretResource, versions := range secrets {
		for version, value := range versions {
			fakeStore.SetVersion(secretResource, version, []byte(value))
		}
	}

	// Create engine and reseal
	engine := NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)
	_, err = engine.ResealOne(ctx, "golden-"+name)
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	// Read output
	manifestPath := filepath.Join(dir, metadata.ManifestPath)
	actualData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	// Compare
	expected := normalizeYAML(string(expectedData))
	actual := normalizeYAML(string(actualData))

	if expected != actual {
		t.Errorf("output mismatch for %s:\n\nExpected:\n%s\n\nActual:\n%s", name, expected, actual)
	}
}

// normalizeYAML removes trailing whitespace and ensures consistent line endings.
func normalizeYAML(s string) string {
	lines := strings.Split(s, "\n")
	var normalized []string
	for _, line := range lines {
		// Trim trailing whitespace
		line = strings.TrimRight(line, " \t\r")
		normalized = append(normalized, line)
	}
	// Remove trailing empty lines
	for len(normalized) > 0 && normalized[len(normalized)-1] == "" {
		normalized = normalized[:len(normalized)-1]
	}
	return strings.Join(normalized, "\n")
}

// TestGolden_KeyOrdering verifies keys are alphabetically sorted.
func TestGolden_KeyOrdering(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Setup
	metadataDir := filepath.Join(dir, ".waxseal", "metadata")
	os.MkdirAll(metadataDir, 0o755)
	os.MkdirAll(filepath.Join(dir, "apps", "order"), 0o755)

	// Create metadata with keys in non-alphabetical order
	metadata := `shortName: order-test
manifestPath: apps/order/sealed-secret.yaml
sealedSecret:
  name: order-test
  namespace: default
  scope: strict
status: active
keys:
  - keyName: zebra
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/zebra
      version: "1"
    rotation:
      mode: manual
  - keyName: alpha
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/alpha
      version: "1"
    rotation:
      mode: manual
  - keyName: middle
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/middle
      version: "1"
    rotation:
      mode: manual
`
	if err := os.WriteFile(filepath.Join(metadataDir, "order-test.yaml"), []byte(metadata), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Setup store
	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/zebra", "1", []byte("z-value"))
	fakeStore.SetVersion("projects/test/secrets/alpha", "1", []byte("a-value"))
	fakeStore.SetVersion("projects/test/secrets/middle", "1", []byte("m-value"))

	// Reseal
	engine := NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)
	_, err := engine.ResealOne(ctx, "order-test")
	if err != nil {
		t.Fatalf("ResealOne failed: %v", err)
	}

	// Read manifest
	manifestPath := filepath.Join(dir, "apps", "order", "sealed-secret.yaml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	// Find the order of keys in output
	lines := strings.Split(string(content), "\n")
	var keyOrder []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "alpha:") ||
			strings.HasPrefix(line, "middle:") ||
			strings.HasPrefix(line, "zebra:") {
			parts := strings.Split(line, ":")
			keyOrder = append(keyOrder, parts[0])
		}
	}

	// Verify alphabetical order
	expected := []string{"alpha", "middle", "zebra"}
	if len(keyOrder) != len(expected) {
		t.Errorf("expected %d keys, got %d: %v", len(expected), len(keyOrder), keyOrder)
	}
	for i, key := range keyOrder {
		if key != expected[i] {
			t.Errorf("key[%d] = %q, want %q", i, key, expected[i])
		}
	}
}

// TestGolden_Idempotency verifies running reseal twice produces identical output.
func TestGolden_Idempotency(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Setup
	metadataDir := filepath.Join(dir, ".waxseal", "metadata")
	os.MkdirAll(metadataDir, 0o755)
	os.MkdirAll(filepath.Join(dir, "apps", "idem"), 0o755)

	metadata := `shortName: idem-test
manifestPath: apps/idem/sealed-secret.yaml
sealedSecret:
  name: idem-test
  namespace: default
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
	if err := os.WriteFile(filepath.Join(metadataDir, "idem-test.yaml"), []byte(metadata), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	fakeStore := store.NewFakeStore()
	fakeStore.SetVersion("projects/test/secrets/secret", "1", []byte("secret-value"))

	engine := NewEngine(fakeStore, seal.NewFakeSealer(), dir, false)

	// First reseal
	_, err := engine.ResealOne(ctx, "idem-test")
	if err != nil {
		t.Fatalf("first ResealOne failed: %v", err)
	}

	manifestPath := filepath.Join(dir, "apps", "idem", "sealed-secret.yaml")
	first, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}

	// Second reseal
	_, err = engine.ResealOne(ctx, "idem-test")
	if err != nil {
		t.Fatalf("second ResealOne failed: %v", err)
	}

	second, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}

	// Compare
	if string(first) != string(second) {
		t.Errorf("reseal not idempotent:\n\nFirst:\n%s\n\nSecond:\n%s", string(first), string(second))
	}
}
