// Package e2e contains end-to-end tests for WaxSeal.
// These tests run against a real Kubernetes cluster (kind) with Sealed Secrets installed.
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

var (
	testClusterName = "waxseal-e2e"
	testNamespace   = "waxseal-test"
	testRepoDir     string
)

// TestMain sets up and tears down the kind cluster for all E2E tests.
func TestMain(m *testing.M) {
	// Skip if not in E2E mode
	if os.Getenv("WAXSEAL_E2E") == "" {
		os.Exit(0)
	}

	// Create temp directory for test repo
	var err error
	testRepoDir, err = os.MkdirTemp("", "waxseal-e2e-*")
	if err != nil {
		panic(err)
	}

	// Setup cluster
	if err := setupCluster(); err != nil {
		panic(err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if os.Getenv("WAXSEAL_E2E_KEEP_CLUSTER") == "" {
		teardownCluster()
	}
	os.RemoveAll(testRepoDir)

	os.Exit(code)
}

func setupCluster() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Check if cluster already exists
	cmd := exec.CommandContext(ctx, "kind", "get", "clusters")
	output, _ := cmd.Output()
	if strings.Contains(string(output), testClusterName) {
		// Cluster exists, just use it
		return nil
	}

	// Create kind cluster
	configPath := filepath.Join(getProjectRoot(), "tests", "e2e", "kind-config.yaml")
	cmd = exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", testClusterName,
		"--config", configPath,
		"--wait", "120s",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// Install Sealed Secrets controller
	if err := installSealedSecrets(ctx); err != nil {
		return err
	}

	// Wait for controller to be ready
	time.Sleep(10 * time.Second)

	// Create test namespace
	cmd = exec.CommandContext(ctx, "kubectl", "create", "namespace", testNamespace)
	cmd.Run() // Ignore error if exists

	return nil
}

func teardownCluster() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kind", "delete", "cluster", "--name", testClusterName)
	cmd.Run()
}

func installSealedSecrets(ctx context.Context) error {
	// Add Sealed Secrets Helm repo
	cmd := exec.CommandContext(ctx, "helm", "repo", "add", "sealed-secrets",
		"https://bitnami-labs.github.io/sealed-secrets")
	cmd.Run()

	cmd = exec.CommandContext(ctx, "helm", "repo", "update")
	cmd.Run()

	// Install Sealed Secrets
	cmd = exec.CommandContext(ctx, "helm", "install", "sealed-secrets",
		"sealed-secrets/sealed-secrets",
		"--namespace", "kube-system",
		"--set", "fullnameOverride=sealed-secrets-controller",
		"--wait",
		"--timeout", "120s",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getProjectRoot() string {
	// Walk up to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// Helper to run waxseal commands
func runWaxseal(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("waxseal", args...)
	cmd.Dir = testRepoDir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Helper to run kubectl
func runKubectl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Helper to run waxseal with a specific working directory
func runWaxsealWithDir(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("waxseal", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// fetchClusterCert gets the sealing certificate from the kind cluster
func fetchClusterCert(t *testing.T) []byte {
	t.Helper()
	cmd := exec.Command("kubeseal", "--fetch-cert",
		"--controller-name=sealed-secrets-controller",
		"--controller-namespace=kube-system")
	output, err := cmd.Output()
	if err != nil {
		t.Logf("Warning: could not fetch cluster cert: %v", err)
		return nil
	}
	return output
}

// setupTestRepoWithCert creates a test repo with a real certificate from the cluster
func setupTestRepoWithCert(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "waxseal-e2e-*")
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

	// Fetch real cert from cluster
	os.MkdirAll(filepath.Join(tmpDir, "keys"), 0o755)
	cert := fetchClusterCert(t)
	if cert != nil {
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), cert, 0o644)
	} else {
		// Use placeholder for unit-test-like scenarios
		os.WriteFile(filepath.Join(tmpDir, "keys/pub-cert.pem"), []byte("placeholder"), 0o644)
	}

	return tmpDir
}
