package ops

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/testutil"
)

// The golden fixtures were produced by the old reseal engine; the new
// Reseal must reproduce them byte for byte.
func TestGolden_Opaque(t *testing.T) {
	runGolden(t, "opaque", map[string]map[string]string{
		"projects/test/secrets/password": {"1": "password-value"},
		"projects/test/secrets/api-key":  {"2": "api-key-value"},
		"projects/test/secrets/username": {"1": "user-value"},
	})
}

func TestGolden_Docker(t *testing.T) {
	runGolden(t, "docker", map[string]map[string]string{
		"projects/test/secrets/docker-config": {"1": "docker-config-value"},
	})
}

func TestGolden_Computed(t *testing.T) {
	runGolden(t, "computed", map[string]map[string]string{
		"projects/test/secrets/db-user": {"1": "admin"},
		"projects/test/secrets/db-pass": {"1": "secret123"},
	})
}

func runGolden(t *testing.T, name string, secrets map[string]map[string]string) {
	t.Helper()
	dir := t.TempDir()
	goldenDir := filepath.Join("..", "..", "testdata", "golden")
	input, err := os.ReadFile(filepath.Join(goldenDir, "input_"+name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := core.ParseMetadata(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".waxseal", "metadata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".waxseal", "metadata", "golden-"+name+".yaml"), input, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := repo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewFakeStore()
	for resource, versions := range secrets {
		for v, value := range versions {
			st.SetVersion(resource, v, []byte(value))
		}
	}
	s := &Service{Repo: r, Store: st, Sealer: seal.NewFakeSealer(), Now: func() time.Time { return fixedNow }}

	results, err := s.Reseal(context.Background(), ResealInput{ShortNames: []string{"golden-" + name}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Error != "" {
		t.Fatalf("reseal: %s", results[0].Error)
	}
	got, err := os.ReadFile(filepath.Join(dir, m.ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertGolden(t, filepath.Join(goldenDir, "expected_"+name+".yaml"), got)

	// Resealing again with the same inputs is a no-op on disk.
	if _, err := s.Reseal(context.Background(), ResealInput{ShortNames: []string{"golden-" + name}}); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, m.ManifestPath))
	if string(again) != string(got) {
		t.Error("reseal is not idempotent")
	}
}
