package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Sealer encrypts secret data using a public certificate.
type Sealer interface {
	// Seal encrypts a single key-value pair for a specific scope.
	// Returns the base64-encoded encrypted value.
	Seal(name, namespace, key string, value []byte, scope string) (string, error)
}

// CertSealer seals secrets using a PEM-encoded certificate.
type CertSealer struct {
	cert *x509.Certificate
}

// NewCertSealerFromFile creates a sealer from a PEM certificate file.
func NewCertSealerFromFile(certPath string) (*CertSealer, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(certPath, err)
		}
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	return NewCertSealerFromPEM(data)
}

// NewCertSealerFromPEM creates a sealer from PEM-encoded certificate data.
func NewCertSealerFromPEM(pemData []byte) (*CertSealer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, core.NewValidationError("certificate", "failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, core.WrapValidation("certificate", err)
	}

	// Verify it's an RSA public key (required for sealed secrets)
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, core.NewValidationError("certificate", "must contain RSA public key")
	}

	return &CertSealer{cert: cert}, nil
}

// Seal encrypts a value for the given secret metadata.
// The scope affects how the label is constructed for encryption.
func (s *CertSealer) Seal(name, namespace, key string, value []byte, scope string) (string, error) {
	// Construct the label based on scope
	// This label is used in the encryption process to bind the ciphertext
	// to specific metadata, preventing reuse across different contexts
	var label []byte
	switch scope {
	case ScopeStrict:
		// Bound to namespace/name/key
		label = []byte(fmt.Sprintf("%s/%s/%s", namespace, name, key))
	case ScopeNamespaceWide:
		// Bound to namespace only
		label = []byte(namespace)
	case ScopeClusterWide:
		// No binding
		label = []byte{}
	default:
		// Default to strict
		label = []byte(fmt.Sprintf("%s/%s/%s", namespace, name, key))
	}

	// Use hybrid encryption (RSA-OAEP + AES-GCM)
	encrypted, err := hybridEncrypt(s.cert, value, label)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return encrypted, nil
}

// GetCertFingerprint returns the SHA256 fingerprint of the certificate.
func (s *CertSealer) GetCertFingerprint() string {
	return fmt.Sprintf("%x", sha256Sum(s.cert.Raw))
}

// GetCertNotAfter returns the certificate's expiry time.
func (s *CertSealer) GetCertNotAfter() time.Time {
	return s.cert.NotAfter
}

// GetCertNotBefore returns the certificate's start time.
func (s *CertSealer) GetCertNotBefore() time.Time {
	return s.cert.NotBefore
}

// IsExpired returns true if the certificate has expired.
func (s *CertSealer) IsExpired() bool {
	return time.Now().After(s.cert.NotAfter)
}

// ExpiresWithinDays returns true if the certificate expires within n days.
func (s *CertSealer) ExpiresWithinDays(days int) bool {
	threshold := time.Now().AddDate(0, 0, days)
	return s.cert.NotAfter.Before(threshold)
}

// DaysUntilExpiry returns the number of days until the certificate expires.
// Returns negative if already expired.
func (s *CertSealer) DaysUntilExpiry() int {
	duration := time.Until(s.cert.NotAfter)
	return int(duration.Hours() / 24)
}

// GetSubject returns the certificate subject.
func (s *CertSealer) GetSubject() string {
	return s.cert.Subject.String()
}

// GetIssuer returns the certificate issuer.
func (s *CertSealer) GetIssuer() string {
	return s.cert.Issuer.String()
}

// FakeSealer is a test implementation that returns predictable output.
type FakeSealer struct {
	// Prefix to add to "encrypted" values for testing
	Prefix string
}

// NewFakeSealer creates a fake sealer for testing.
func NewFakeSealer() *FakeSealer {
	return &FakeSealer{Prefix: "SEALED:"}
}

// Seal returns a fake encrypted value for testing.
func (s *FakeSealer) Seal(name, namespace, key string, value []byte, scope string) (string, error) {
	// Return a deterministic fake encrypted value
	return fmt.Sprintf("%s%s/%s/%s=%s", s.Prefix, namespace, name, key, string(value)), nil
}

// Compile-time interface checks
var (
	_ Sealer = (*CertSealer)(nil)
	_ Sealer = (*FakeSealer)(nil)
)

// hybridEncrypt performs RSA-OAEP + AES-GCM hybrid encryption.
func hybridEncrypt(cert *x509.Certificate, plaintext, label []byte) (string, error) {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("certificate does not contain RSA public key")
	}

	// Generate a random AES key
	aesKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", fmt.Errorf("generate AES key: %w", err)
	}

	// Encrypt the AES key with RSA-OAEP
	hash := sha256.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, aesKey, label)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt: %w", err)
	}

	// Encrypt the plaintext with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Combine: len(encryptedKey) || encryptedKey || ciphertext
	var result bytes.Buffer
	keyLen := uint16(len(encryptedKey))
	result.WriteByte(byte(keyLen >> 8))
	result.WriteByte(byte(keyLen))
	result.Write(encryptedKey)
	result.Write(ciphertext)

	return base64.StdEncoding.EncodeToString(result.Bytes()), nil
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
