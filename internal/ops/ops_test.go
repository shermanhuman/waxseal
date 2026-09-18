package ops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

// fixedNow is inside the fixture cert's validity and before every fixture
// expiry, so tests are deterministic.
var fixedNow = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

var errBoom = errors.New("boom")

// fakeCluster serves secrets from a map keyed "namespace/name".
type fakeCluster struct {
	secrets map[string]map[string][]byte
	err     error
}

func (f *fakeCluster) GetSecret(_ context.Context, namespace, name string) (map[string][]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	data, ok := f.secrets[namespace+"/"+name]
	if !ok {
		return nil, core.WrapNotFound("secret "+namespace+"/"+name, nil)
	}
	return data, nil
}

// fakeCerts returns a fixed certificate.
type fakeCerts struct {
	pem []byte
	err error
}

func (f *fakeCerts) FetchCert(context.Context, string, string) ([]byte, error) { return f.pem, f.err }

// newFixtureService copies testdata/infra-repo into a temp dir and wires the
// fakes around it.
func newFixtureService(t *testing.T) (*Service, *store.FakeStore) {
	t.Helper()
	dir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "testdata", "infra-repo"), dir)
	r, err := repo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := r.Config()
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewFakeStore()
	return &Service{
		Repo:      r,
		Config:    cfg,
		Store:     st,
		Sealer:    seal.NewFakeSealer(),
		Now:       func() time.Time { return fixedNow },
		ProjectID: cfg.Store.ProjectID,
	}, st
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
}

// seedStore puts every GSM version the fixture metadata references into the
// fake store, with a recognisable value.
func seedStore(t *testing.T, s *Service, st *store.FakeStore) {
	t.Helper()
	secrets, errs := s.Repo.AllMetadata()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, m := range secrets {
		for _, k := range m.Keys {
			if ref := k.ActiveRef(); ref != nil {
				st.SetVersion(ref.SecretResource, ref.Version, []byte("value-of-"+k.KeyName))
			}
		}
	}
}

func findingsBy(findings []Finding, check, severity string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Check == check && f.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}
