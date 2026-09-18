package seal

import (
	"encoding/pem"
	"testing"
	"time"
)

func TestParseCert(t *testing.T) {
	info, err := ParseCert(generateTestCertPEM(t))
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	if len(info.Fingerprint()) != 64 {
		t.Errorf("Fingerprint() = %q, want 64 hex chars", info.Fingerprint())
	}
	// Whole days, from a clock the caller controls.
	if got := info.DaysLeft(info.NotAfter().Add(-49 * time.Hour)); got != 2 {
		t.Errorf("DaysLeft 49h before expiry = %d, want 2", got)
	}
	if got := info.DaysLeft(info.NotAfter().Add(30 * time.Hour)); got != -1 {
		t.Errorf("DaysLeft 30h after expiry = %d, want -1", got)
	}

	for name, bad := range map[string][]byte{
		"placeholder": []byte("# fetch the cert first\n"),
		"wrong type":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"garbage":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
	} {
		if _, err := ParseCert(bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
