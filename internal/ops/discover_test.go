package ops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shermanhuman/waxseal/internal/seal"
)

func TestDiscover(t *testing.T) {
	s, _ := newFixtureService(t)

	// An unregistered manifest, plus a non-SealedSecret YAML and a dot-dir
	// that must both be ignored.
	extra := seal.NewSealedSecret("web", "frontend/team", "namespace-wide", "Opaque", map[string]string{"b": "x", "a": "y"})
	data, _ := extra.ToYAML()
	root := s.Repo.Root()
	for path, content := range map[string][]byte{
		"apps/web/sealed.yml":        data,
		"apps/web/deployment.yaml":   []byte("kind: Deployment\nmetadata: {name: web}\n"),
		".hidden/sealed-secret.yaml": data,
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	found, err := s.Discover()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Discovered{}
	for _, d := range found {
		byPath[d.Path] = d
	}
	if len(found) != 4 {
		t.Errorf("found %d manifests, want 4: %v", len(found), byPath)
	}
	reg := byPath["apps/my-app/sealed-secret.yaml"]
	if reg.Registered != "my-app-secrets" {
		t.Errorf("fixture manifest: %+v", reg)
	}
	web := byPath["apps/web/sealed.yml"]
	if web.Registered != "" || web.Suggested != "frontend-team-web" || web.Scope != "namespace-wide" || len(web.Keys) != 2 || web.Keys[0] != "a" {
		t.Errorf("new manifest: %+v", web)
	}
}
