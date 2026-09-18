package repo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	r, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return r
}

func sampleMetadata(version string) *core.SecretMetadata {
	return &core.SecretMetadata{
		ShortName:    "app",
		ManifestPath: "apps/app/sealed-secret.yaml",
		SealedSecret: core.SealedSecretRef{Name: "app", Namespace: "prod", Scope: "strict"},
		Status:       "active",
		Keys: []core.KeyMetadata{{
			KeyName: "password",
			Source:  core.SourceConfig{Kind: "gsm"},
			GSM:     &core.GSMRef{SecretResource: "projects/p/secrets/app-password", Version: version},
		}},
	}
}

func sampleManifest() *seal.SealedSecret {
	return seal.NewSealedSecret("app", "prod", seal.ScopeStrict, "Opaque", map[string]string{"password": "SEALED"})
}

// assertNoTempFiles fails if a write left a staging file behind.
func assertNoTempFiles(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(d.Name(), ".tmp") {
			t.Errorf("staging file left behind: %s", path)
		}
		return nil
	})
}

func TestOpen(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); !core.IsNotFound(err) {
		t.Errorf("missing dir: got %v, want not found", err)
	}
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Error("expected an error opening a file as a repo")
	}
}

func TestMetadata_WriteThenLoad(t *testing.T) {
	r := newRepo(t)
	want := sampleMetadata("3")

	if _, err := r.Metadata("app"); !core.IsNotFound(err) {
		t.Fatalf("before write: got %v, want not found", err)
	}
	if err := r.WriteMetadata(want); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	got, err := r.Metadata("app")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	assertNoTempFiles(t, r.Root())
}

func TestWriteMetadata_RejectsBeforeTouchingDisk(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*core.SecretMetadata)
	}{
		{"alias GSM version", func(m *core.SecretMetadata) { m.Keys[0].GSM.Version = "latest" }},
		{"no keys", func(m *core.SecretMetadata) { m.Keys = nil }},
		{"manifest path escapes the repo", func(m *core.SecretMetadata) { m.ManifestPath = "../outside.yaml" }},
		{"absolute manifest path", func(m *core.SecretMetadata) { m.ManifestPath = "/etc/passwd" }},
		{"short name with a separator", func(m *core.SecretMetadata) { m.ShortName = "a/b" }},
		{"short name that climbs", func(m *core.SecretMetadata) { m.ShortName = ".." }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRepo(t)
			m := sampleMetadata("1")
			tt.mutate(m)
			if err := r.WriteMetadata(m); err == nil {
				t.Fatal("expected an error")
			}
			entries, _ := os.ReadDir(r.Root())
			if len(entries) != 0 {
				t.Errorf("rejected write still created %d entries under the repo", len(entries))
			}
		})
	}
}

func TestAllMetadata(t *testing.T) {
	r := newRepo(t)
	if secrets, errs := r.AllMetadata(); len(secrets) != 0 || len(errs) != 0 {
		t.Fatalf("empty repo: got %d secrets, %v", len(secrets), errs)
	}

	for _, name := range []string{"zeta", "alpha"} {
		m := sampleMetadata("1")
		m.ShortName = name
		if err := r.WriteMetadata(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(r.MetadataPath("broken"), []byte("shortName: [unclosed"), 0o644); err != nil {
		t.Fatal(err)
	}

	secrets, errs := r.AllMetadata()
	if len(secrets) != 2 || secrets[0].ShortName != "alpha" || secrets[1].ShortName != "zeta" {
		t.Errorf("got %d secrets, want alpha then zeta", len(secrets))
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "broken") {
		t.Errorf("errs = %v, want one error naming the broken file", errs)
	}
}

func TestCommit_WritesBoth(t *testing.T) {
	r := newRepo(t)
	m := sampleMetadata("1")
	if err := r.Commit(m, sampleManifest()); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := r.Metadata("app"); err != nil {
		t.Errorf("metadata: %v", err)
	}
	ss, err := r.Manifest(m)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if ss.Spec.EncryptedData["password"] != "SEALED" {
		t.Errorf("manifest content not written: %+v", ss.Spec.EncryptedData)
	}
	assertNoTempFiles(t, r.Root())
}

func TestCommit_InvalidInputChangesNothing(t *testing.T) {
	tests := []struct {
		name     string
		manifest func() *seal.SealedSecret
	}{
		{"manifest for a different secret", func() *seal.SealedSecret {
			return seal.NewSealedSecret("other", "prod", seal.ScopeStrict, "Opaque", map[string]string{"k": "v"})
		}},
		{"manifest that would not parse back", func() *seal.SealedSecret {
			ss := sampleManifest()
			ss.Kind = "Secret"
			return ss
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRepo(t)
			if err := r.Commit(sampleMetadata("1"), sampleManifest()); err != nil {
				t.Fatal(err)
			}
			if err := r.Commit(sampleMetadata("2"), tt.manifest()); err == nil {
				t.Fatal("expected an error")
			}
			got, err := r.Metadata("app")
			if err != nil {
				t.Fatal(err)
			}
			if v := got.Keys[0].GSM.Version; v != "1" {
				t.Errorf("metadata version = %s, want it untouched at 1", v)
			}
			assertNoTempFiles(t, r.Root())
		})
	}
}

// The GSM version pointer cannot be recovered from anywhere else, so it must
// be on disk even when putting the manifest in place fails. A stale manifest
// is repaired by resealing.
func TestCommit_MetadataLandsBeforeManifest(t *testing.T) {
	r := newRepo(t)
	m := sampleMetadata("7")

	// A directory where the manifest should go makes the final rename fail.
	manifestPath, err := r.ManifestPath(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(manifestPath, "in-the-way"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := r.Commit(m, sampleManifest()); err == nil {
		t.Fatal("expected the manifest rename to fail")
	}
	got, err := r.Metadata("app")
	if err != nil {
		t.Fatalf("metadata was not written: %v", err)
	}
	if v := got.Keys[0].GSM.Version; v != "7" {
		t.Errorf("metadata version = %s, want 7", v)
	}
	assertNoTempFiles(t, r.Root())
}

func TestManifest_NotFoundAndDelete(t *testing.T) {
	r := newRepo(t)
	m := sampleMetadata("1")
	if _, err := r.Manifest(m); !core.IsNotFound(err) {
		t.Errorf("got %v, want not found", err)
	}
	if err := r.DeleteManifest(m); err != nil {
		t.Errorf("deleting a missing manifest: %v", err)
	}
	if err := r.Commit(m, sampleManifest()); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteManifest(m); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Manifest(m); !core.IsNotFound(err) {
		t.Errorf("after delete: got %v, want not found", err)
	}
}

func TestCert(t *testing.T) {
	r := newRepo(t)
	const rel = "keys/pub-cert.pem"

	if _, err := r.Cert(rel); !core.IsNotFound(err) {
		t.Errorf("got %v, want not found", err)
	}
	for name, bad := range map[string][]byte{
		"placeholder comment": []byte("# fetch the cert with kubeseal --fetch-cert\n"),
		"wrong PEM type":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"garbage certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
	} {
		if err := r.WriteCert(rel, bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := r.Cert(rel); !core.IsNotFound(err) {
		t.Error("a rejected certificate must not be written")
	}

	good := testCertPEM(t)
	if err := r.WriteCert(rel, good); err != nil {
		t.Fatalf("WriteCert: %v", err)
	}
	got, err := r.Cert(rel)
	if err != nil || string(got) != string(good) {
		t.Errorf("Cert() = %q, %v", got, err)
	}
	if err := r.WriteCert("../escape.pem", good); err == nil {
		t.Error("expected an error for a path outside the repo")
	}
}

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sealed-secrets"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
