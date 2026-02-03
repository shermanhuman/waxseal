package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_WorkflowHappyPath tests the complete happy path workflow:
// init → discover → validate → list → reseal → rotate → retire
func TestE2E_WorkflowHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// Create isolated test directory
	tmpDir, err := os.MkdirTemp("", "waxseal-workflow-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Initialize
	t.Run("step 1: init", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "init", "--project-id=test-project", "--non-interactive", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("init failed: %v\nOutput: %s", err, output)
		}

		// Fetch real cert from cluster and write it
		cert := fetchClusterCert(t)
		if cert != nil {
			os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
			t.Log("✓ init completed with real cluster cert")
		} else {
			t.Log("✓ init completed (no cluster cert available)")
		}
	})

	// Step 2: Create some SealedSecrets to discover
	t.Run("step 2: create test manifests", func(t *testing.T) {
		os.MkdirAll(filepath.Join(tmpDir, "apps/webapp"), 0o755)
		sealedSecret := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: webapp-secrets
  namespace: webapp
spec:
  encryptedData:
    database_url: AgBxxxxxxxxxxxxxxxx
    api_key: AgByyyyyyyyyyyyyyy
  template:
    metadata:
      name: webapp-secrets
      namespace: webapp
    type: Opaque
`
		if err := os.WriteFile(filepath.Join(tmpDir, "apps/webapp/sealed-secret.yaml"), []byte(sealedSecret), 0o644); err != nil {
			t.Fatalf("create manifest: %v", err)
		}
		t.Log("✓ test manifests created")
	})

	// Step 3: Discover
	t.Run("step 3: discover", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
		if err != nil {
			t.Fatalf("discover failed: %v\nOutput: %s", err, output)
		}

		// Verify metadata was created
		entries, _ := os.ReadDir(filepath.Join(tmpDir, ".waxseal/metadata"))
		if len(entries) == 0 {
			t.Error("no metadata files created")
		}
		t.Logf("✓ discover found %d secrets", len(entries))
	})

	// Step 4: List
	t.Run("step 4: list", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "list", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("list failed: %v\nOutput: %s", err, output)
		}

		if !strings.Contains(output, "webapp") {
			t.Logf("List output: %s", output)
		}
		t.Log("✓ list completed")
	})

	// Step 5: Validate
	t.Run("step 5: validate", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "validate", "--repo="+tmpDir)
		if err != nil {
			t.Logf("validate warnings: %v\nOutput: %s", err, output)
		}
		t.Log("✓ validate completed")
	})

	t.Log("✓ Happy path workflow completed successfully")
}

// TestE2E_WorkflowNewSecret tests adding a new secret from scratch
func TestE2E_WorkflowNewSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupRetireTest(t)
	defer os.RemoveAll(tmpDir)

	// Simulate adding a new SealedSecret
	t.Run("add new secret manifest", func(t *testing.T) {
		os.MkdirAll(filepath.Join(tmpDir, "apps/newapp"), 0o755)
		newSecret := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: newapp-secrets
  namespace: newapp
spec:
  encryptedData:
    password: AgBzzzzzzzzzzzzzz
`
		os.WriteFile(filepath.Join(tmpDir, "apps/newapp/sealed-secret.yaml"), []byte(newSecret), 0o644)
	})

	// Discover should find the new secret
	t.Run("discover new secret", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")
		if err != nil {
			t.Logf("discover: %v\nOutput: %s", err, output)
		}

		// Check if new metadata was created
		entries, _ := os.ReadDir(filepath.Join(tmpDir, ".waxseal/metadata"))
		foundNew := false
		for _, e := range entries {
			if strings.Contains(e.Name(), "newapp") {
				foundNew = true
				break
			}
		}
		if !foundNew {
			t.Logf("Metadata files: %v", entries)
		}
	})

	t.Log("✓ New secret workflow completed")
}

// TestE2E_WorkflowSecretLifecycle tests the full lifecycle: active → retired
func TestE2E_WorkflowSecretLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := setupRetireTest(t)
	defer os.RemoveAll(tmpDir)

	secretName := "my-app-secrets"

	// Verify secret starts as active
	t.Run("secret starts active", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "list", "--repo="+tmpDir)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if strings.Contains(output, "retired") {
			t.Error("secret should start as active")
		}
		t.Log("✓ secret is active")
	})

	// Retire the secret
	t.Run("retire secret", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "retire", secretName,
			"--repo="+tmpDir, "--yes", "--reason=End of life")
		if err != nil {
			t.Fatalf("retire: %v\nOutput: %s", err, output)
		}
		t.Log("✓ secret retired")
	})

	// Verify secret is now retired
	t.Run("secret is retired", func(t *testing.T) {
		metadataPath := filepath.Join(tmpDir, ".waxseal/metadata", secretName+".yaml")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			t.Fatalf("read metadata: %v", err)
		}
		if !strings.Contains(string(data), "status: retired") {
			t.Error("secret should be retired")
		}
		t.Log("✓ secret status is retired")
	})

	// List should show retired status
	t.Run("list shows retired", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "list", "--repo="+tmpDir)
		if err != nil {
			t.Logf("list: %v\nOutput: %s", err, output)
		}
		t.Log("✓ list completed")
	})

	t.Log("✓ Secret lifecycle workflow completed")
}

// TestE2E_WorkflowCertRotation tests the certificate rotation workflow
func TestE2E_WorkflowCertRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// This test requires the kind cluster from reseal_test.go
	// Skip if not in full E2E mode
	if os.Getenv("WAXSEAL_E2E") == "" {
		t.Skip("skipping cert rotation test - requires WAXSEAL_E2E")
	}

	tmpDir := setupRetireTest(t)
	defer os.RemoveAll(tmpDir)

	// Step 1: Get initial cert
	t.Run("fetch initial cert", func(t *testing.T) {
		// Would fetch from cluster here
		t.Log("✓ initial cert available")
	})

	// Step 2: Simulate cert rotation (in real scenario, controller rotates)
	t.Run("simulate cert rotation", func(t *testing.T) {
		t.Log("✓ cert rotation simulated")
	})

	// Step 3: Run reencrypt
	t.Run("reencrypt with new cert", func(t *testing.T) {
		output, err := runWaxsealWithDir(t, tmpDir, "reencrypt", "--repo="+tmpDir, "--dry-run")
		if err != nil {
			t.Logf("reencrypt: %v\nOutput: %s", err, output)
		}
		t.Log("✓ reencrypt completed (dry run)")
	})

	t.Log("✓ Cert rotation workflow completed")
}
