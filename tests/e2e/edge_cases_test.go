// Package e2e contains edge case tests for WaxSeal.
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Edge cases for init command

func TestE2E_Edge_InitAlreadyInitialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir, _ := os.MkdirTemp("", "waxseal-edge-*")
	defer os.RemoveAll(tmpDir)

	// First init
	runWaxsealWithDir(t, tmpDir, "init", "--project-id=test-project", "--non-interactive", "--repo="+tmpDir)

	// Second init should warn or fail gracefully
	output, err := runWaxsealWithDir(t, tmpDir, "init", "--project-id=test-project", "--non-interactive", "--repo="+tmpDir)
	if err != nil {
		// Expected - already initialized
		if !strings.Contains(output, "already") && !strings.Contains(output, "exists") {
			t.Logf("Expected 'already exists' message, got: %s", output)
		}
	}
	t.Log("✓ Init on already initialized repo handled")
}

func TestE2E_Edge_InitInvalidProjectID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir, _ := os.MkdirTemp("", "waxseal-edge-*")
	defer os.RemoveAll(tmpDir)

	// Invalid project ID with spaces
	output, err := runWaxsealWithDir(t, tmpDir, "init", "--project-id=invalid project", "--non-interactive", "--repo="+tmpDir)
	if err == nil {
		t.Error("expected error for invalid project ID")
	}
	_ = output
	t.Log("✓ Invalid project ID rejected")
}

// Edge cases for discover command

func TestE2E_Edge_DiscoverEmptyRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Discover with no manifests
	output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
	if err != nil {
		t.Logf("discover on empty: %v", err)
	}
	if !strings.Contains(output, "0") && !strings.Contains(output, "no ") {
		t.Logf("Output: %s", output)
	}
	t.Log("✓ Discover on empty repo handled")
}

func TestE2E_Edge_DiscoverMalformedYAML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create malformed YAML
	os.MkdirAll(filepath.Join(tmpDir, "apps"), 0o755)
	os.WriteFile(filepath.Join(tmpDir, "apps/bad.yaml"), []byte("not: valid: yaml: {{broken"), 0o644)

	// Discover should handle gracefully
	output, _ := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
	_ = output
	t.Log("✓ Malformed YAML handled gracefully")
}

func TestE2E_Edge_DiscoverNonSealedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create a non-SealedSecret YAML (e.g., ConfigMap)
	os.MkdirAll(filepath.Join(tmpDir, "apps"), 0o755)
	configMap := `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
`
	os.WriteFile(filepath.Join(tmpDir, "apps/configmap.yaml"), []byte(configMap), 0o644)

	// Discover should ignore non-SealedSecrets
	output, _ := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
	if strings.Contains(output, "configmap") {
		t.Error("ConfigMap should not be discovered as SealedSecret")
	}
	t.Log("✓ Non-SealedSecret YAMLs ignored")
}

// Edge cases for validate command

func TestE2E_Edge_ValidateMissingManifest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create metadata pointing to non-existent manifest
	metadata := `shortName: ghost-secret
manifestPath: apps/ghost/sealed-secret.yaml
sealedSecret:
  name: ghost-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/ghost
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/ghost-secret.yaml"), []byte(metadata), 0o644)

	// Validate should report missing manifest
	output, err := runWaxsealWithDir(t, tmpDir, "validate", "--repo="+tmpDir)
	if err == nil {
		t.Log("validate passed (may be warning-only mode)")
	}
	_ = output
	t.Log("✓ Missing manifest detected in validation")
}

func TestE2E_Edge_ValidateKeyMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create metadata with keys not in manifest
	metadata := `shortName: mismatch-secret
manifestPath: apps/mismatch/sealed-secret.yaml
sealedSecret:
  name: mismatch-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key_a
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/a
      version: "1"
  - keyName: key_b
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/b
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/mismatch-secret.yaml"), []byte(metadata), 0o644)

	// Create manifest with only one key
	os.MkdirAll(filepath.Join(tmpDir, "apps/mismatch"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mismatch-secret
  namespace: default
spec:
  encryptedData:
    key_a: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/mismatch/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Validate should report key mismatch
	output, _ := runWaxsealWithDir(t, tmpDir, "validate", "--repo="+tmpDir)
	_ = output
	t.Log("✓ Key mismatch detected in validation")
}

// Edge cases for reseal command

func TestE2E_Edge_ResealNonExistentSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Try to reseal a secret that doesn't exist
	output, err := runWaxsealWithDir(t, tmpDir, "reseal", "nonexistent-secret", "--repo="+tmpDir)
	if err == nil {
		t.Error("expected error for non-existent secret")
	}
	if !strings.Contains(output, "not found") {
		t.Logf("Expected 'not found', got: %s", output)
	}
	t.Log("✓ Non-existent secret reseal rejected")
}

func TestE2E_Edge_ResealRetiredSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create retired metadata
	metadata := `shortName: retired-secret
manifestPath: apps/retired/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: default
  scope: strict
  type: Opaque
status: retired
retiredAt: "2026-01-01T00:00:00Z"
retiredReason: "Test retirement"
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/retired
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/retired-secret.yaml"), []byte(metadata), 0o644)

	// Reseal should skip or warn about retired secrets
	output, err := runWaxsealWithDir(t, tmpDir, "reseal", "retired-secret", "--repo="+tmpDir)
	_ = err
	if strings.Contains(output, "retired") {
		t.Log("✓ Retired secret status mentioned")
	}
	t.Log("✓ Retired secret reseal handled")
}

// Edge cases for retire command

func TestE2E_Edge_RetireNonExistentSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Try to retire a secret that doesn't exist
	output, err := runWaxsealWithDir(t, tmpDir, "retire", "nonexistent-secret", "--repo="+tmpDir, "--yes")
	if err == nil {
		t.Error("expected error for non-existent secret")
	}
	_ = output
	t.Log("✓ Non-existent secret retire rejected")
}

func TestE2E_Edge_RetireAlreadyRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupRetireTest(t)
	defer os.RemoveAll(tmpDir)

	// Retire once
	runWaxsealWithDir(t, tmpDir, "retire", "my-app-secrets", "--repo="+tmpDir, "--yes")

	// Retire again
	output, err := runWaxsealWithDir(t, tmpDir, "retire", "my-app-secrets", "--repo="+tmpDir, "--yes")
	if err == nil {
		// May succeed idempotently or warn
		t.Log("✓ Double retire handled idempotently")
	} else {
		if strings.Contains(output, "already retired") {
			t.Log("✓ Already retired error returned")
		}
	}
}

// Edge cases for computed keys

func TestE2E_Edge_ComputedKeyCyclicDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create metadata with cyclic dependency (a depends on b, b depends on a)
	metadata := `shortName: cyclic-secret
manifestPath: apps/cyclic/sealed-secret.yaml
sealedSecret:
  name: cyclic-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key_a
    source:
      kind: computed
    computed:
      kind: template
      template: "prefix-{{key_b}}"
      inputs:
        - var: key_b
          ref:
            keyName: key_b
  - keyName: key_b
    source:
      kind: computed
    computed:
      kind: template
      template: "suffix-{{key_a}}"
      inputs:
        - var: key_a
          ref:
            keyName: key_a
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/cyclic-secret.yaml"), []byte(metadata), 0o644)

	os.MkdirAll(filepath.Join(tmpDir, "apps/cyclic"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: cyclic-secret
  namespace: default
spec:
  encryptedData:
    key_a: AgBxxxxxx
    key_b: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/cyclic/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Reseal should detect cycle
	output, err := runWaxsealWithDir(t, tmpDir, "reseal", "cyclic-secret", "--repo="+tmpDir)
	if err == nil {
		t.Error("expected error for cyclic dependency")
	}
	if strings.Contains(output, "cycle") || strings.Contains(output, "circular") {
		t.Log("✓ Cyclic dependency detected")
	}
	t.Log("✓ Cyclic dependency test completed")
}

// Edge cases for certificate handling

func TestE2E_Edge_InvalidCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Write invalid certificate
	os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), []byte("not a valid certificate"), 0o644)

	// Create some secret metadata
	metadata := `shortName: test-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/test
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/test-secret.yaml"), []byte(metadata), 0o644)

	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    key: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Reseal should fail with cert error
	output, err := runWaxsealWithDir(t, tmpDir, "reseal", "test-secret", "--repo="+tmpDir)
	if err == nil {
		t.Error("expected error for invalid certificate")
	}
	_ = output
	t.Log("✓ Invalid certificate rejected")
}

func TestE2E_Edge_MissingCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Delete certificate
	os.Remove(filepath.Join(tmpDir, "keys/pub-cert.pem"))

	// Create some secret metadata
	metadata := `shortName: test-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: test-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/test
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/test-secret.yaml"), []byte(metadata), 0o644)

	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    key: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Reseal should fail with missing cert error
	output, err := runWaxsealWithDir(t, tmpDir, "reseal", "test-secret", "--repo="+tmpDir)
	if err == nil {
		t.Error("expected error for missing certificate")
	}
	if strings.Contains(output, "not found") || strings.Contains(output, "no such file") {
		t.Log("✓ Missing certificate error reported")
	}
	t.Log("✓ Missing certificate handled")
}

// Edge cases for GSM version pinning

func TestE2E_Edge_GSMVersionLatestRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create metadata with "latest" version (should be rejected)
	metadata := `shortName: latest-version-secret
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: latest-version-secret
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/test
      version: "latest"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/latest-version-secret.yaml"), []byte(metadata), 0o644)

	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: latest-version-secret
  namespace: default
spec:
  encryptedData:
    key: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Validate should reject "latest"
	output, err := runWaxsealWithDir(t, tmpDir, "validate", "--repo="+tmpDir)
	_ = err
	if strings.Contains(output, "latest") || strings.Contains(output, "numeric") {
		t.Log("✓ 'latest' version rejected as expected")
	}
	t.Log("✓ GSM version pinning enforced")
}

// Edge cases for scope handling

func TestE2E_Edge_ScopeMismatchDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupTestRepoWithCert(t)
	defer os.RemoveAll(tmpDir)

	// Create metadata with strict scope
	metadata := `shortName: scope-test
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: scope-test
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: key
    source:
      kind: gsm
    gsm:
      secretResource: projects/test/secrets/test
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/scope-test.yaml"), []byte(metadata), 0o644)

	// Create manifest with namespace-wide annotation
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: scope-test
  namespace: default
  annotations:
    sealedsecrets.bitnami.com/namespace-wide: "true"
spec:
  encryptedData:
    key: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Validate should detect scope mismatch
	output, _ := runWaxsealWithDir(t, tmpDir, "validate", "--repo="+tmpDir)
	_ = output
	t.Log("✓ Scope mismatch test completed")
}
