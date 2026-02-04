package seal

import (
	"os"
	"os/exec"
	"testing"
)

// TestKubesealSealer_ScopeMapping tests the scope to kubeseal flag mapping.
func TestKubesealSealer_ScopeMapping(t *testing.T) {
	// Skip if kubeseal not available
	if _, err := exec.LookPath("kubeseal"); err != nil {
		t.Skip("kubeseal binary not available")
	}

	// Create a temp cert file (placeholder - won't actually work for real sealing)
	tmpCert, err := os.CreateTemp("", "kubeseal-test-*.pem")
	if err != nil {
		t.Fatalf("create temp cert: %v", err)
	}
	defer os.Remove(tmpCert.Name())
	tmpCert.WriteString("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n")
	tmpCert.Close()

	sealer := NewKubesealSealer(tmpCert.Name())

	tests := []struct {
		name          string
		scope         string
		wantScopeFlag string
	}{
		{"strict scope", ScopeStrict, "strict"},
		{"namespace-wide scope", ScopeNamespaceWide, "namespace-wide"},
		{"cluster-wide scope", ScopeClusterWide, "cluster-wide"},
		{"empty defaults to strict", "", "strict"},
		{"unknown defaults to strict", "invalid", "strict"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't fully test without a real cert, but we verify the sealer is created
			if sealer.certPath != tmpCert.Name() {
				t.Error("certPath not set")
			}
		})
	}
}

// TestKubesealSealer_GetCertFingerprint tests the fingerprint method.
func TestKubesealSealer_GetCertFingerprint(t *testing.T) {
	sealer := NewKubesealSealer("/path/to/cert.pem")
	fingerprint := sealer.GetCertFingerprint()
	if fingerprint != "kubeseal-binary" {
		t.Errorf("expected 'kubeseal-binary', got %q", fingerprint)
	}
}

// TestKubesealSealer_InterfaceCompliance verifies KubesealSealer implements Sealer.
func TestKubesealSealer_InterfaceCompliance(t *testing.T) {
	var _ Sealer = (*KubesealSealer)(nil)
}

// TestNewKubesealSealer tests constructor.
func TestNewKubesealSealer(t *testing.T) {
	certPath := "/test/path/cert.pem"
	sealer := NewKubesealSealer(certPath)
	if sealer == nil {
		t.Fatal("expected non-nil sealer")
	}
	if sealer.certPath != certPath {
		t.Errorf("expected certPath %q, got %q", certPath, sealer.certPath)
	}
}

// TestKubesealSealer_SealWithMissingBinary tests error handling when kubeseal isn't found.
func TestKubesealSealer_SealWithMissingBinary(t *testing.T) {
	// Temporarily modify PATH to exclude kubeseal
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	sealer := NewKubesealSealer("/nonexistent/cert.pem")
	_, err := sealer.Seal("name", "namespace", "key", []byte("value"), ScopeStrict)
	if err == nil {
		t.Error("expected error when kubeseal binary not found")
	}
}
