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

func TestCertExpiryMethods(t *testing.T) {
	// Create a test certificate that expires in 90 days
	cert, err := generateTestCert(90)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	sealer := &CertSealer{cert: cert}

	// Test IsExpired
	if sealer.IsExpired() {
		t.Error("expected cert to not be expired")
	}

	// Test DaysUntilExpiry
	days := sealer.DaysUntilExpiry()
	if days < 89 || days > 91 {
		t.Errorf("expected ~90 days until expiry, got %d", days)
	}

	// Test ExpiresWithinDays
	if !sealer.ExpiresWithinDays(100) {
		t.Error("expected ExpiresWithinDays(100) to be true")
	}
	if sealer.ExpiresWithinDays(30) {
		t.Error("expected ExpiresWithinDays(30) to be false")
	}

	// Test GetCertFingerprint
	fp := sealer.GetCertFingerprint()
	if len(fp) != 64 {
		t.Errorf("expected fingerprint length 64, got %d", len(fp))
	}
}

func TestCertExpired(t *testing.T) {
	// Create an expired certificate (-30 days in the past)
	cert, err := generateTestCertWithDates(
		time.Now().AddDate(0, 0, -60),
		time.Now().AddDate(0, 0, -30),
	)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	sealer := &CertSealer{cert: cert}

	if !sealer.IsExpired() {
		t.Error("expected cert to be expired")
	}

	days := sealer.DaysUntilExpiry()
	if days >= 0 {
		t.Errorf("expected negative days until expiry, got %d", days)
	}
}

func TestCertExpiringSoon(t *testing.T) {
	// Create a certificate that expires in 15 days
	cert, err := generateTestCert(15)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	sealer := &CertSealer{cert: cert}

	// Should warn at 30 days
	if !sealer.ExpiresWithinDays(30) {
		t.Error("expected ExpiresWithinDays(30) to be true for 15-day cert")
	}

	// Should not warn at 7 days
	if sealer.ExpiresWithinDays(7) {
		t.Error("expected ExpiresWithinDays(7) to be false for 15-day cert")
	}
}

// generateTestCert creates a test certificate that expires in the given number of days.
func generateTestCert(daysUntilExpiry int) (*x509.Certificate, error) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, daysUntilExpiry)
	return generateTestCertWithDates(notBefore, notAfter)
}

// generateTestCertWithDates creates a test certificate with specific validity dates.
func generateTestCertWithDates(notBefore, notAfter time.Time) (*x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sealed-secrets-test",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// generateExpiryTestCertPEM creates a test certificate PEM for use in expiry tests.
func generateExpiryTestCertPEM(daysUntilExpiry int) ([]byte, error) {
	cert, err := generateTestCert(daysUntilExpiry)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}
