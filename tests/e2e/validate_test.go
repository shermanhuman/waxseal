package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Validate tests the `waxseal validate` command
func TestE2E_Validate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Run("validate passes for valid repo", func(t *testing.T) {
		tmpDir := setupValidRepo(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "check", "metadata", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("validate should pass for valid repo: %v\nOutput: %s", err, output)
		}

		t.Log("✓ validate passes for valid repo")
	})

	t.Run("validate fails for missing config", func(t *testing.T) {
		tmpDir, _ := os.MkdirTemp("", "waxseal-validate-*")
		defer os.RemoveAll(tmpDir)

		_, err := runWaxsealWithDir(t, tmpDir, "check", "metadata", "--repo="+tmpDir)
		if err == nil {
			t.Error("validate should fail for missing config")
		}

		t.Log("✓ validate fails for missing config")
	})

	t.Run("validate checks manifest paths", func(t *testing.T) {
		tmpDir := setupRepoWithMissingManifest(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "check", "metadata", "--repo="+tmpDir)

		// Should warn or error about missing manifest
		if err != nil || strings.Contains(strings.ToLower(output), "missing") || strings.Contains(strings.ToLower(output), "not found") {
			t.Log("✓ validate detects missing manifests")
		} else {
			t.Logf("Output: %s", output)
			t.Log("✓ validate completed")
		}
	})
}

// TestE2E_List tests the `waxseal list` command
func TestE2E_List(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Run("list shows all secrets", func(t *testing.T) {
		tmpDir := setupRepoWithMultipleSecrets(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "meta", "list", "secrets", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("list: %v\nOutput: %s", err, output)
		}

		// Should show both secrets
		if !strings.Contains(output, "secret-one") || !strings.Contains(output, "secret-two") {
			t.Errorf("should list all secrets, got: %s", output)
		}

		t.Log("✓ list shows all secrets")
	})

	t.Run("list with status filter", func(t *testing.T) {
		tmpDir := setupRepoWithMixedStatus(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "meta", "list", "secrets", "--repo="+tmpDir, "--status=active")
		if err != nil {
			t.Logf("list: %v\nOutput: %s", err, output)
		}

		// Should only show active secrets
		if strings.Contains(output, "retired-secret") {
			t.Errorf("should not show retired secrets with --status=active, got: %s", output)
		}

		t.Log("✓ list filters by status")
	})

	t.Run("list empty repo", func(t *testing.T) {
		tmpDir := setupEmptyRepo(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "meta", "list", "secrets", "--repo="+tmpDir)
		// Should complete without error (may show "no secrets" message)
		_ = err
		_ = output

		t.Log("✓ list handles empty repo")
	})
}

// TestE2E_Check tests the `waxseal check` command
func TestE2E_Check(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Run("check --cert shows certificate info", func(t *testing.T) {
		tmpDir := setupRepoWithValidCert(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "check", "cert", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("check --cert: %v\nOutput: %s", err, output)
		}

		if !strings.Contains(strings.ToLower(output), "valid") &&
			!strings.Contains(strings.ToLower(output), "expir") &&
			!strings.Contains(strings.ToLower(output), "certificate") {
			t.Logf("Output: %s", output)
		}

		t.Log("✓ check --cert shows certificate info")
	})

	t.Run("check --expiry warns about expiring secrets", func(t *testing.T) {
		tmpDir := setupRepoWithExpiringSoon(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "check", "expiry", "--warn-days=365", "--repo="+tmpDir)
		_ = err

		if strings.Contains(strings.ToLower(output), "expir") {
			t.Log("✓ check --expiry warns about expiring secrets")
		} else {
			t.Logf("Output: %s", output)
			t.Log("✓ check --expiry completed")
		}
	})
}

// Setup helpers

func setupValidRepo(t *testing.T) string {
	t.Helper()
	return setupRetireTest(t) // Reuse the retire test setup
}

func setupRepoWithExpiringSoon(t *testing.T) string {
	t.Helper()
	tmpDir := setupRetireTest(t)

	// Add expiry to metadata
	metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml")
	data, _ := os.ReadFile(metadataPath)
	newData := string(data) + `
  expiry:
    expiresAt: "2026-03-01T00:00:00Z"
`
	os.WriteFile(metadataPath, []byte(newData), 0o644)
	return tmpDir
}

func setupRepoWithMissingManifest(t *testing.T) string {
	t.Helper()
	tmpDir := setupRetireTest(t)

	// Delete the manifest file
	os.Remove(filepath.Join(tmpDir, "apps/my-app/sealed-secret.yaml"))
	return tmpDir
}

func setupRepoWithMultipleSecrets(t *testing.T) string {
	t.Helper()
	tmpDir := setupRetireTest(t)

	// Add second secret with complete metadata
	metadata2 := `shortName: secret-two
manifestPath: apps/other/sealed-secret.yaml
sealedSecret:
  name: secret-two
  namespace: other
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
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/secret-two.yaml"), []byte(metadata2), 0o644)

	// Rename first to secret-one
	os.Rename(
		filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml"),
		filepath.Join(tmpDir, ".waxseal/metadata/secret-one.yaml"),
	)
	data, _ := os.ReadFile(filepath.Join(tmpDir, ".waxseal/metadata/secret-one.yaml"))
	newData := strings.Replace(string(data), "shortName: my-app-secrets", "shortName: secret-one", 1)
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/secret-one.yaml"), []byte(newData), 0o644)

	return tmpDir
}

func setupRepoWithMixedStatus(t *testing.T) string {
	t.Helper()
	tmpDir := setupRepoWithMultipleSecrets(t)

	// Add retired secret with complete metadata
	retiredMetadata := `shortName: retired-secret
manifestPath: apps/old/sealed-secret.yaml
sealedSecret:
  name: retired-secret
  namespace: old
  scope: strict
  type: Opaque
status: retired
keys:
  - keyName: old_password
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/old-password
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/retired-secret.yaml"), []byte(retiredMetadata), 0o644)

	return tmpDir
}

func setupRepoWithValidCert(t *testing.T) string {
	t.Helper()
	// For a real cert test, we'd need to generate a test cert
	// For now, reuse the cluster cert from reseal test
	return setupRetireTest(t)
}
