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
