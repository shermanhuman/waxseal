package repo

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Cert reads the controller certificate (PEM) stored at the repo-relative
// path. It returns an error wrapping core.ErrNotFound when it has not been
// fetched yet.
func (r *Repo) Cert(relPath string) ([]byte, error) {
	path, err := r.resolve("cert.repoCertPath", relPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound("certificate "+relPath, err)
		}
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return data, nil
}

// WriteCert atomically stores the controller certificate after checking that
// it really is a PEM-encoded X.509 certificate.
func (r *Repo) WriteCert(relPath string, pemData []byte) error {
	path, err := r.resolve("cert.repoCertPath", relPath)
	if err != nil {
		return err
	}
	return write(path, pemData, validateCert)
}

func validateCert(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("not a PEM-encoded certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	return nil
}
