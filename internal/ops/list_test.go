package ops

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestList(t *testing.T) {
	s, _ := newFixtureService(t)
	rows, errs := s.List(30)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.ShortName)
	}
	if !reflect.DeepEqual(names, []string{"docker-registry", "my-app-secrets", "tls-cert"}) {
		t.Errorf("names = %v", names)
	}
	for _, r := range rows {
		if r.ShortName != "my-app-secrets" {
			continue
		}
		if r.KeyCount != 4 || r.Status != "active" || r.Namespace != "my-app" {
			t.Errorf("row = %+v", r)
		}
		if !reflect.DeepEqual(r.RotationModes, []string{"external", "generated", "static", "unknown"}) {
			t.Errorf("rotation modes = %v", r.RotationModes)
		}
		if r.Expiry != "" {
			t.Errorf("expiry = %q, want none on %s", r.Expiry, fixedNow)
		}
	}

	// Expiry is judged against the injected clock.
	s.Now = func() time.Time { return fixedNow.AddDate(0, 4, 0) }
	rows, _ = s.List(30)
	if rows[2].Expiry != "expired" || rows[1].Expiry != "" {
		t.Errorf("four months on: tls-cert = %q (want expired), my-app-secrets = %q (want none)", rows[2].Expiry, rows[1].Expiry)
	}
}

func TestList_ReportsBrokenFilesAndKeepsTheRest(t *testing.T) {
	s, _ := newFixtureService(t)
	if err := os.WriteFile(s.Repo.MetadataPath("broken"), []byte("keys: [oops"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, errs := s.List(30)
	if len(rows) != 3 || len(errs) != 1 {
		t.Errorf("got %d rows, %d errors; want 3 and 1", len(rows), len(errs))
	}
}

func TestShow(t *testing.T) {
	s, _ := newFixtureService(t)
	v, err := s.Show("my-app-secrets")
	if err != nil {
		t.Fatal(err)
	}
	if v.Namespace != "my-app" || v.Scope != "strict" || v.Type != "Opaque" || len(v.Keys) != 4 {
		t.Errorf("view = %+v", v)
	}
	byName := map[string]KeyView{}
	for _, k := range v.Keys {
		byName[k.Name] = k
	}
	pw := byName["database_password"]
	if pw.RotationMode != "generated" || pw.Generator != "randomBase64" || pw.GSMVersion != "3" || pw.DaysLeft != nil {
		t.Errorf("database_password = %+v", pw)
	}
	api := byName["api_key"]
	if api.RotationMode != "external" || api.ExpiresAt != "2026-06-15T00:00:00Z" || api.DaysLeft == nil || *api.DaysLeft != 151 {
		t.Errorf("api_key = %+v", api)
	}
	url := byName["DATABASE_URL"]
	if url.Source != "computed" || url.Template == "" || url.RotationMode != "unknown" || url.GSMResource != "" {
		t.Errorf("DATABASE_URL = %+v", url)
	}

	if _, err := s.Show("nope"); !core.IsNotFound(err) {
		t.Errorf("unknown secret: got %v", err)
	}
}

func TestActiveMetadata(t *testing.T) {
	s, _ := newFixtureService(t)
	if _, err := s.activeMetadata(""); !errors.As(err, new(*MissingInputError)) {
		t.Errorf("empty name: got %v", err)
	}
	if _, err := s.activeMetadata("nope"); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("unknown: got %v", err)
	}
	m, _ := s.Repo.Metadata("tls-cert")
	m.Status = "retired"
	if err := s.Repo.WriteMetadata(m); err != nil {
		t.Fatal(err)
	}
	if _, err := s.activeMetadata("tls-cert"); !errors.Is(err, core.ErrRetired) {
		t.Errorf("retired: got %v", err)
	}
	if got := s.ActiveSecretNames(); !reflect.DeepEqual(got, []string{"docker-registry", "my-app-secrets"}) {
		t.Errorf("ActiveSecretNames = %v", got)
	}
}
