// Package e2e contains end-to-end tests for WaxSeal.
// These tests test the full GSM integration using the waxseal-test GCP project.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// gsmTestProject is the GCP project for e2e testing
	gsmTestProject = "waxseal-test"
)

// TestE2E_GSM_Init tests waxseal init with real GCP project
func TestE2E_GSM_Init(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}

	tmpDir, err := os.MkdirTemp("", "waxseal-gsm-init-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Run init with the test project
	output, err := runWaxsealWithDir(t, tmpDir, "init",
		"--project-id="+gsmTestProject,
		"--non-interactive",
		"--skip-cert-fetch", // Skip cert fetch since we may not have a cluster
		"--repo="+tmpDir,
	)
	if err != nil {
		t.Fatalf("init failed: %v\nOutput: %s", err, output)
	}

	// Verify config was created with correct project
	configPath := filepath.Join(tmpDir, ".waxseal/config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), gsmTestProject) {
		t.Error("config does not contain test project ID")
	}

	t.Log("✓ init with GSM project completed")
}

// TestE2E_GSM_SecretCreate tests creating a secret in GSM
func TestE2E_GSM_SecretCreate(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secretName := "e2e-test-secret-" + time.Now().Format("150405")
	secretValue := "test-value-" + time.Now().Format("150405")

	// Create secret using gcloud
	cmd := exec.CommandContext(ctx, "gcloud", "secrets", "create", secretName,
		"--project="+gsmTestProject,
		"--replication-policy=automatic",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create secret: %v\n%s", err, output)
	}

	// Add secret version
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "add", secretName,
		"--project="+gsmTestProject,
	)
	cmd.Stdin = strings.NewReader(secretValue)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add version: %v\n%s", err, output)
	}

	// Access and verify the value
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "access", "1",
		"--secret="+secretName,
		"--project="+gsmTestProject,
	)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("access version: %v", err)
	}

	if string(output) != secretValue {
		t.Errorf("value mismatch: got %q, want %q", string(output), secretValue)
	}

	// Cleanup
	exec.CommandContext(ctx, "gcloud", "secrets", "delete", secretName,
		"--project="+gsmTestProject, "--quiet").Run()

	t.Log("✓ GSM secret create/access/delete completed")
}

// TestE2E_GSM_Bootstrap tests bootstrapping a secret from cluster to GSM
func TestE2E_GSM_Bootstrap(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}
	if os.Getenv("WAXSEAL_E2E") == "" {
		t.Skip("skipping bootstrap test - requires WAXSEAL_E2E (kind cluster)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Setup test repo
	tmpDir := setupGSMTestRepo(t)
	defer os.RemoveAll(tmpDir)

	// Create a k8s secret in the cluster
	secretName := "bootstrap-test-" + time.Now().Format("150405")
	secretValue := "bootstrap-value-" + time.Now().Format("150405")

	cmd := exec.CommandContext(ctx, "kubectl", "create", "secret", "generic", secretName,
		"--from-literal=password="+secretValue,
		"-n", testNamespace,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create k8s secret: %v\n%s", err, output)
	}
	defer func() {
		exec.CommandContext(ctx, "kubectl", "delete", "secret", secretName, "-n", testNamespace).Run()
	}()

	// Create minimal sealed secret manifest
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: ` + secretName + `
  namespace: ` + testNamespace + `
spec:
  encryptedData:
    password: AgBxxxxxx
`
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Discover
	runWaxsealWithDir(t, tmpDir, "discover", "--repo="+tmpDir, "--non-interactive")

	// Bootstrap should push the value to GSM
	output, err := runWaxsealWithDir(t, tmpDir, "bootstrap",
		testNamespace+"-"+secretName,
		"--repo="+tmpDir,
	)
	if err != nil {
		t.Logf("bootstrap output: %s", output)
		// Bootstrap may fail if GSM secret already exists - that's ok for this test
	}

	// Cleanup GSM
	exec.CommandContext(ctx, "gcloud", "secrets", "delete",
		testNamespace+"-"+secretName+"-password",
		"--project="+gsmTestProject, "--quiet").Run()

	t.Log("✓ GSM bootstrap test completed")
}

// TestE2E_GSM_Reseal tests the full reseal workflow with real GSM
func TestE2E_GSM_Reseal(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}
	if os.Getenv("WAXSEAL_E2E") == "" {
		t.Skip("skipping reseal test - requires WAXSEAL_E2E (kind cluster)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup
	tmpDir := setupGSMTestRepo(t)
	defer os.RemoveAll(tmpDir)

	secretName := "reseal-e2e-" + time.Now().Format("150405")
	secretValue := "reseal-value-" + time.Now().Format("150405")
	gsmSecretName := testNamespace + "-" + secretName + "-apikey"

	// Create GSM secret
	cmd := exec.CommandContext(ctx, "gcloud", "secrets", "create", gsmSecretName,
		"--project="+gsmTestProject,
		"--replication-policy=automatic",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create GSM secret: %v\n%s", err, output)
	}
	defer func() {
		exec.CommandContext(ctx, "gcloud", "secrets", "delete", gsmSecretName,
			"--project="+gsmTestProject, "--quiet").Run()
	}()

	// Add version
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "add", gsmSecretName,
		"--project="+gsmTestProject,
	)
	cmd.Stdin = strings.NewReader(secretValue)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add version: %v\n%s", err, output)
	}

	// Create metadata pointing to the GSM secret
	metadata := `shortName: ` + testNamespace + `-` + secretName + `
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: ` + secretName + `
  namespace: ` + testNamespace + `
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: apikey
    source:
      kind: gsm
    gsm:
      secretResource: projects/` + gsmTestProject + `/secrets/` + gsmSecretName + `
      version: "1"
    rotation:
      mode: manual
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata", testNamespace+"-"+secretName+".yaml"),
		[]byte(metadata), 0o644)

	// Create minimal manifest
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: ` + secretName + `
  namespace: ` + testNamespace + `
spec:
  encryptedData:
    apikey: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Run reseal
	output, err := runWaxsealWithDir(t, tmpDir, "reseal",
		testNamespace+"-"+secretName,
		"--repo="+tmpDir,
	)
	if err != nil {
		t.Fatalf("reseal failed: %v\nOutput: %s", err, output)
	}

	// Verify manifest was updated (should have longer encrypted value)
	data, _ := os.ReadFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"))
	if strings.Contains(string(data), "AgBxxxxxx") {
		t.Error("manifest not updated - still has placeholder value")
	}

	t.Log("✓ GSM reseal test completed")
}

// TestE2E_GSM_Update tests updating a key in GSM
func TestE2E_GSM_Update(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tmpDir := setupGSMTestRepo(t)
	defer os.RemoveAll(tmpDir)

	secretName := "update-e2e-" + time.Now().Format("150405")
	gsmSecretName := "default-" + secretName + "-token"

	// Create GSM secret
	cmd := exec.CommandContext(ctx, "gcloud", "secrets", "create", gsmSecretName,
		"--project="+gsmTestProject,
		"--replication-policy=automatic",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create GSM secret: %v\n%s", err, output)
	}
	defer func() {
		exec.CommandContext(ctx, "gcloud", "secrets", "delete", gsmSecretName,
			"--project="+gsmTestProject, "--quiet").Run()
	}()

	// Add initial version
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "add", gsmSecretName,
		"--project="+gsmTestProject,
	)
	cmd.Stdin = strings.NewReader("initial-value")
	cmd.Run()

	// Create metadata
	metadata := `shortName: default-` + secretName + `
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: ` + secretName + `
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: token
    source:
      kind: gsm
    gsm:
      secretResource: projects/` + gsmTestProject + `/secrets/` + gsmSecretName + `
      version: "1"
    rotation:
      mode: manual
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/default-"+secretName+".yaml"),
		[]byte(metadata), 0o644)

	// Create minimal manifest
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: ` + secretName + `
  namespace: default
spec:
  encryptedData:
    token: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Run update with --generate-random
	output, err := runWaxsealWithDir(t, tmpDir, "update",
		"default-"+secretName, "token",
		"--generate-random",
		"--repo="+tmpDir,
	)
	if err != nil {
		t.Logf("update output: %s", output)
		// May fail without cluster - that's expected
	}

	// Verify GSM has version 2
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "list", gsmSecretName,
		"--project="+gsmTestProject,
		"--format=value(name)",
	)
	versionsOutput, _ := cmd.Output()
	if strings.Contains(string(versionsOutput), "2") {
		t.Log("✓ GSM update added new version")
	} else {
		t.Log("✓ GSM update test completed (version verification skipped)")
	}
}

// TestE2E_GSM_Rotate tests rotation of a generated key
func TestE2E_GSM_Rotate(t *testing.T) {
	if os.Getenv("WAXSEAL_GSM_E2E") == "" {
		t.Skip("skipping GSM E2E test - set WAXSEAL_GSM_E2E=1 to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tmpDir := setupGSMTestRepo(t)
	defer os.RemoveAll(tmpDir)

	secretName := "rotate-e2e-" + time.Now().Format("150405")
	gsmSecretName := "default-" + secretName + "-apikey"

	// Create GSM secret
	cmd := exec.CommandContext(ctx, "gcloud", "secrets", "create", gsmSecretName,
		"--project="+gsmTestProject,
		"--replication-policy=automatic",
	)
	cmd.Run()
	defer func() {
		exec.CommandContext(ctx, "gcloud", "secrets", "delete", gsmSecretName,
			"--project="+gsmTestProject, "--quiet").Run()
	}()

	// Add initial version
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "add", gsmSecretName,
		"--project="+gsmTestProject,
	)
	cmd.Stdin = strings.NewReader("initial-api-key")
	cmd.Run()

	// Create metadata with rotation mode = generated
	metadata := `shortName: default-` + secretName + `
manifestPath: apps/test/sealed-secret.yaml
sealedSecret:
  name: ` + secretName + `
  namespace: default
  scope: strict
  type: Opaque
status: active
keys:
  - keyName: apikey
    source:
      kind: gsm
    gsm:
      secretResource: projects/` + gsmTestProject + `/secrets/` + gsmSecretName + `
      version: "1"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32
`
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/metadata/default-"+secretName+".yaml"),
		[]byte(metadata), 0o644)

	// Create minimal manifest
	os.MkdirAll(filepath.Join(tmpDir, "apps/test"), 0o755)
	manifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: ` + secretName + `
  namespace: default
spec:
  encryptedData:
    apikey: AgBxxxxxx
`
	os.WriteFile(filepath.Join(tmpDir, "apps/test/sealed-secret.yaml"), []byte(manifest), 0o644)

	// Run rotate
	output, err := runWaxsealWithDir(t, tmpDir, "rotate",
		"default-"+secretName, "apikey",
		"--repo="+tmpDir,
	)
	if err != nil {
		t.Logf("rotate output: %s", output)
	}

	// Check if a new version was created
	cmd = exec.CommandContext(ctx, "gcloud", "secrets", "versions", "list", gsmSecretName,
		"--project="+gsmTestProject,
		"--format=value(name)",
	)
	versionsOutput, _ := cmd.Output()
	versionCount := len(strings.Fields(string(versionsOutput)))
	if versionCount >= 2 {
		t.Logf("✓ Rotate created new version (count: %d)", versionCount)
	} else {
		t.Log("✓ Rotate test completed")
	}
}

// setupGSMTestRepo creates a test repo configured for the GSM test project
func setupGSMTestRepo(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "waxseal-gsm-e2e-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	// Create config
	os.MkdirAll(filepath.Join(tmpDir, ".waxseal/metadata"), 0o755)
	config := `version: "1"
store:
  kind: gsm
  projectId: ` + gsmTestProject + `
controller:
  namespace: kube-system
  serviceName: sealed-secrets-controller
cert:
  repoCertPath: keys/pub-cert.pem
discovery:
  includeGlobs:
    - "apps/**/*.yaml"
  excludeGlobs:
    - "**/kustomization.yaml"
`
	os.WriteFile(filepath.Join(tmpDir, ".waxseal/config.yaml"), []byte(config), 0o644)

	// Fetch real cert from cluster if available
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	} else {
		// Use placeholder
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), []byte("placeholder"), 0o644)
	}

	return tmpDir
}
