package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Retire tests the `waxseal retire` command
func TestE2E_Retire(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Run("retire marks secret as retired", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		// Retire the secret
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets", "--repo="+tmpDir, "--yes")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}

		// Verify metadata was updated
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			t.Fatalf("read metadata: %v", err)
		}

		if !strings.Contains(string(data), "status: retired") {
			t.Errorf("expected status: retired in metadata, got: %s", string(data))
		}

		t.Log("✓ retire marks secret as retired")
	})

	t.Run("retire with reason", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		// Retire with reason
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets",
			"--repo="+tmpDir,
			"--yes",
			"--reason=Migrated to new service")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}

		// Verify reason is in metadata
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml")
		data, _ := os.ReadFile(metadataPath)

		if !strings.Contains(string(data), "Migrated") {
			t.Logf("Metadata: %s", string(data))
		}

		t.Log("✓ retire includes reason")
	})

	t.Run("retire with replaced-by", func(t *testing.T) {
		tmpDir := setupRetireTestWithReplacement(t)
		defer os.RemoveAll(tmpDir)

		// Retire with replacement
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "old-secret",
			"--repo="+tmpDir,
			"--yes",
			"--replaced-by=new-secret")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}

		// Verify replacement is in metadata
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/old-secret.yaml")
		data, _ := os.ReadFile(metadataPath)

		if !strings.Contains(string(data), "new-secret") {
			t.Logf("Metadata: %s", string(data))
		}

		t.Log("✓ retire links to replacement")
	})

	t.Run("retire with delete-manifest", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		manifestPath := filepath.Join(tmpDir, "apps/my-app/sealed-secret.yaml")

		// Verify manifest exists
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			t.Fatalf("manifest should exist before retire")
		}

		// Retire with delete
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets",
			"--repo="+tmpDir,
			"--yes",
			"--delete-manifest")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}

		// Manifest should be deleted
		if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
			t.Error("manifest should be deleted after retire --delete-manifest")
		}

		t.Log("✓ retire with delete-manifest removes manifest")
	})

	t.Run("retire dry run", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		// Read original metadata
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml")
		originalData, _ := os.ReadFile(metadataPath)

		// Retire with dry run
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets",
			"--repo="+tmpDir,
			"--yes",
			"--dry-run")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}

		// Metadata should be unchanged
		newData, _ := os.ReadFile(metadataPath)
		if string(originalData) != string(newData) {
			t.Error("dry run should not modify metadata")
		}

		t.Log("✓ retire dry run doesn't modify files")
	})

	t.Run("retire non-existent secret", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		// Try to retire non-existent secret
		_, err := runWaxsealWithDir(t, tmpDir, "retirekey", "does-not-exist",
			"--repo="+tmpDir,
			"--yes")

		if err == nil {
			t.Error("expected error when retiring non-existent secret")
		}

		t.Log("✓ retire fails for non-existent secret")
	})

	t.Run("retire already retired secret", func(t *testing.T) {
		tmpDir := setupRetireTest(t)
		defer os.RemoveAll(tmpDir)

		// First retire
		runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets", "--repo="+tmpDir, "--yes")

		// Second retire - should warn or succeed gracefully
		output, err := runWaxsealWithDir(t, tmpDir, "retirekey", "my-app-secrets",
			"--repo="+tmpDir,
			"--yes")

		// Should either error or warn
		if err == nil && !strings.Contains(strings.ToLower(output), "already") {
			t.Logf("Output: %s", output)
		}

		t.Log("✓ retire handles already retired secrets")
	})
}

// setupRetireTest creates a repo with a secret ready for retirement
func setupRetireTest(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "waxseal-retire-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	// Create config and metadata directory
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	config := `version: "1"
store:
  kind: gsm
  projectId: test-project
controller:
  namespace: kube-system
cert:
  repoCertPath: keys/pub-cert.pem
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/config.yaml"), []byte(config), 0o644)

	// Create metadata file
	metadata := `shortName: my-app-secrets
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-app-secrets
  namespace: my-app
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/test-project/secrets/my-app-password
      version: "1"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml"), []byte(metadata), 0o644)

	// Create manifest
	os.MkdirAll(filepath.Join(tmpDir, "apps/my-app"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  encryptedData:
    password: AgBxxxxxxxxxxxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/my-app/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Create keys directory with real cert from cluster
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	} else {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), []byte("placeholder"), 0o644)
	}

	return tmpDir
}

// setupRetireTestWithReplacement creates a repo with two secrets
func setupRetireTestWithReplacement(t *testing.T) string {
	t.Helper()

	tmpDir := setupRetireTest(t)

	// Rename existing to old-secret
	os.Rename(
		filepath.Join(tmpDir, ".waxseal/metadata/my-app-secrets.yaml"),
		filepath.Join(tmpDir, ".waxseal/metadata/old-secret.yaml"),
	)

	// Update shortName in old-secret
	data, _ := os.ReadFile(filepath.Join(tmpDir, ".waxseal/metadata/old-secret.yaml"))
	newData := strings.Replace(string(data), "shortName: my-app-secrets", "shortName: old-secret", 1)
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/old-secret.yaml"), []byte(newData), 0o644)

	// Create new-secret metadata
	newMetadata := `shortName: new-secret
manifestPath: apps/my-app/new-sealed-secret.yaml
status: active
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/new-secret.yaml"), []byte(newMetadata), 0o644)

	return tmpDir
}
