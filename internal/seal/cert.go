package seal

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

// CertInfo describes the controller's sealing certificate. Encryption itself
// is delegated to kubeseal; this type only answers questions about the cert.
type CertInfo struct {
	cert *x509.Certificate
}

// ParseCert parses a PEM-encoded certificate and checks it carries an RSA
// public key, which sealed-secrets requires.
func ParseCert(pemData []byte) (*CertInfo, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, core.NewValidationError("certificate", "not a PEM-encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, core.WrapValidation("certificate", err)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, core.NewValidationError("certificate", "must contain an RSA public key")
	}
	return &CertInfo{cert: cert}, nil
}

// Fingerprint returns the hex SHA-256 of the DER certificate.
func (c *CertInfo) Fingerprint() string {
	return fmt.Sprintf("%x", sha256.Sum256(c.cert.Raw))
}

// NotAfter returns the certificate's expiry time.
func (c *CertInfo) NotAfter() time.Time { return c.cert.NotAfter }

// NotBefore returns the start of the certificate's validity.
func (c *CertInfo) NotBefore() time.Time { return c.cert.NotBefore }

// Subject returns the certificate subject.
func (c *CertInfo) Subject() string { return c.cert.Subject.String() }

// DaysLeft returns whole days from now until expiry; negative once expired.
func (c *CertInfo) DaysLeft(now time.Time) int {
	return int(c.cert.NotAfter.Sub(now).Hours() / 24)
}
