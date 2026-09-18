package ops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/seal"
)

func certNotAfter(t *testing.T, pemData []byte) time.Time {
	t.Helper()
	info, err := seal.ParseCert(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return info.NotAfter()
}

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "rotated"},
		NotBefore:    fixedNow.Add(-time.Hour),
		NotAfter:     fixedNow.AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
