package ops

import (
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
