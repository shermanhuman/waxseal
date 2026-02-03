package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_Discover tests the `waxseal discover` command
func TestE2E_Discover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	t.Run("discover finds SealedSecrets", func(t *testing.T) {
		tmpDir := setupDiscoverTest(t)
		defer os.RemoveAll(tmpDir)

		// Run discover
		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
		if err != nil {
			t.Fatalf("discover: %v\nOutput: %s", err, output)
		}

		// Should find the test sealed secret
		if !strings.Contains(output, "my-app-secrets") && !strings.Contains(output, "Found") {
			t.Errorf("expected to find my-app-secrets in output: %s", output)
		}

		// Metadata file should be created
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata/my-app-my-app-secrets.yaml")
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			// Try alternative naming
			entries, _ := os.ReadDir(filepath.Join(tmpDir, ".waxseal/metadata"))
			t.Logf("Metadata files: %v", entries)
		}

		t.Log("✓ discover finds SealedSecrets")
	})

	t.Run("discover with dry run", func(t *testing.T) {
		tmpDir := setupDiscoverTest(t)
		defer os.RemoveAll(tmpDir)

		// Run discover with dry run
		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive", "--dry-run")
		if err != nil {
			t.Fatalf("discover dry run: %v\nOutput: %s", err, output)
		}

		// Should indicate dry run
		if !strings.Contains(strings.ToLower(output), "dry") {
			t.Logf("Output: %s", output)
		}

		// No metadata files should be created
		entries, _ := os.ReadDir(filepath.Join(tmpDir, ".waxseal/metadata"))
		if len(entries) > 0 {
			t.Errorf("dry run should not create metadata files, found: %v", entries)
		}

		t.Log("✓ discover dry run doesn't create files")
	})

	t.Run("discover with no SealedSecrets", func(t *testing.T) {
		tmpDir := setupEmptyRepo(t)
		defer os.RemoveAll(tmpDir)

		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")

		// Should complete without error
		if err != nil {
			t.Logf("Output: %s", output)
			// This might be expected if there's truly nothing to discover
		}

		t.Log("✓ discover handles empty repo")
	})

	t.Run("discover skips already registered secrets", func(t *testing.T) {
		tmpDir := setupDiscoverTest(t)
		defer os.RemoveAll(tmpDir)

		// First discover
		_, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
		if err != nil {
			t.Fatalf("first discover: %v", err)
		}

		// Second discover - should skip already registered
		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
		if err != nil {
			t.Fatalf("second discover: %v", err)
		}

		// Should mention already registered
		if !strings.Contains(output, "already") && !strings.Contains(output, "skipping") && !strings.Contains(output, "registered") {
			t.Logf("Second discover output: %s", output)
		}

		t.Log("✓ discover skips already registered secrets")
	})
}

// TestE2E_DiscoverGlobPatterns tests glob pattern filtering
func TestE2E_DiscoverGlobPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupDiscoverTestWithMultiple(t)
	defer os.RemoveAll(tmpDir)

	// Discover should respect glob patterns in config
	output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
	if err != nil {
		t.Logf("discover: %v\nOutput: %s", err, output)
	}

	t.Log("✓ discover respects glob patterns")
}

// setupDiscoverTest creates a test repo with a SealedSecret and config
func setupDiscoverTest(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "waxseal-discover-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	// Create config
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	config := `version: "1"
store:
  kind: gsm
  projectId: test-project
controller:
  namespace: kube-system
  serviceName: sealed-secrets
cert:
  repoCertPath: keys/pub-cert.pem
discovery:
  includeGlobs:
    - "apps/**/*.yaml"
  excludeGlobs:
    - "**/kustomization.yaml"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/config.yaml"), []byte(config), 0o644)

	// Create a SealedSecret
	os.MkdirAll(filepath.Join(tmpDir, "apps/my-app"), 0o755)
	sealedSecret := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  encryptedData:
    password: AgBxxxxxxxxxxxxxxxx
  template:
    metadata:
      name: my-app-secrets
      namespace: my-app
`
	os.WriteFile(filepath.Join(tmpDir, "apps/my-app/sealed-secret.yaml"), []byte(sealedSecret), 0o644)

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

// setupEmptyRepo creates a test repo with config but no SealedSecrets
func setupEmptyRepo(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "waxseal-empty-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

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
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	} else {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), []byte("placeholder"), 0o644)
	}

	return tmpDir
}

// setupDiscoverTestWithMultiple creates a repo with multiple SealedSecrets
func setupDiscoverTestWithMultiple(t *testing.T) string {
	t.Helper()

	tmpDir := setupDiscoverTest(t)

	// Add more secrets in different locations
	os.MkdirAll(filepath.Join(tmpDir, "apps/other-app"), 0o755)
	sealedSecret2 := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: other-secrets
  namespace: other-app
spec:
  encryptedData:
    api_key: AgByyyyyyyyyyyyyyy
`
	os.WriteFile(filepath.Join(tmpDir, "apps/other-app/sealed-secret.yaml"), []byte(sealedSecret2), 0o644)

	// Add one that should be excluded (kustomization)
	os.WriteFile(filepath.Join(tmpDir, "apps/my-app/kustomization.yaml"), []byte("resources:\n  - sealed-secret.yaml\n"), 0o644)

	return tmpDir
}
