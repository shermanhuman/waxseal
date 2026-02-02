package seal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestNewCertSealerFromPEM_Valid(t *testing.T) {
	pemData := generateTestCertPEM(t)

	sealer, err := NewCertSealerFromPEM(pemData)
	if err != nil {
		t.Fatalf("NewCertSealerFromPEM failed: %v", err)
	}

	if sealer.cert == nil {
		t.Error("sealer.cert should not be nil")
	}
}

func TestNewCertSealerFromPEM_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
	}{
		{"empty", []byte{}},
		{"not pem", []byte("not a pem block")},
		{"invalid cert", []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCertSealerFromPEM(tt.pemData)
			if err == nil {
				t.Error("expected error for invalid PEM")
			}
		})
	}
}

func TestCertSealer_Seal(t *testing.T) {
	pemData := generateTestCertPEM(t)
	sealer, err := NewCertSealerFromPEM(pemData)
	if err != nil {
		t.Fatalf("create sealer: %v", err)
	}

	encrypted, err := sealer.Seal("my-secret", "default", "password", []byte("secret-value"), ScopeStrict)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Result should be base64 encoded
	if len(encrypted) == 0 {
		t.Error("encrypted value should not be empty")
	}

	// Each call should produce different ciphertext (due to random nonce)
	encrypted2, _ := sealer.Seal("my-secret", "default", "password", []byte("secret-value"), ScopeStrict)
	if encrypted == encrypted2 {
		t.Error("repeated sealing should produce different ciphertext")
	}
}

func TestCertSealer_Scopes(t *testing.T) {
	pemData := generateTestCertPEM(t)
	sealer, _ := NewCertSealerFromPEM(pemData)

	scopes := []string{ScopeStrict, ScopeNamespaceWide, ScopeClusterWide}
	for _, scope := range scopes {
		t.Run(scope, func(t *testing.T) {
			encrypted, err := sealer.Seal("secret", "ns", "key", []byte("value"), scope)
			if err != nil {
				t.Fatalf("Seal failed for scope %s: %v", scope, err)
			}
			if len(encrypted) == 0 {
				t.Errorf("encrypted value should not be empty for scope %s", scope)
			}
		})
	}
}

func TestCertSealer_GetCertFingerprint(t *testing.T) {
	pemData := generateTestCertPEM(t)
	sealer, _ := NewCertSealerFromPEM(pemData)

	fingerprint := sealer.GetCertFingerprint()
	if len(fingerprint) == 0 {
		t.Error("fingerprint should not be empty")
	}

	// Fingerprint should be consistent
	fingerprint2 := sealer.GetCertFingerprint()
	if fingerprint != fingerprint2 {
		t.Error("fingerprint should be deterministic")
	}
}

func TestFakeSealer(t *testing.T) {
	sealer := NewFakeSealer()

	result, err := sealer.Seal("my-secret", "default", "password", []byte("secret123"), ScopeStrict)
	if err != nil {
		t.Fatalf("FakeSealer.Seal failed: %v", err)
	}

	expected := "SEALED:default/my-secret/password=secret123"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

// generateTestCertPEM generates a self-signed RSA certificate for testing.
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"WaxSeal Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	// Encode to PEM
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}
