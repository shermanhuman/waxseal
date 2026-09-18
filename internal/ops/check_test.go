package ops

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestCheck_AllGreenOnFixture(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	s.Cluster = clusterMatching(t, s)

	findings, err := s.Check(context.Background(), CheckInput{})
	if err != nil {
		t.Fatal(err)
	}
	if sev := MaxSeverity(findings); sev != SeverityInfo {
		t.Errorf("max severity = %s; findings:\n%s", sev, dump(findings))
	}
	for _, name := range Checks.Values() {
		if len(findingsBy(findings, name, SeverityInfo)) == 0 {
			t.Errorf("check %s produced no positive finding", name)
		}
	}
}

func TestCheck_UnknownName(t *testing.T) {
	s, _ := newFixtureService(t)
	if _, err := s.Check(context.Background(), CheckInput{Checks: []string{"vibes"}}); err == nil {
		t.Error("expected an error")
	}
}

func TestCheck_UnavailablePorts(t *testing.T) {
	s, _ := newFixtureService(t)
	s.Store, s.Cluster = nil, nil

	all, _ := s.Check(context.Background(), CheckInput{})
	if n := len(findingsBy(all, CheckGSM, SeverityInfo)) + len(findingsBy(all, CheckCluster, SeverityInfo)); n != 2 {
		t.Errorf("all-checks run should skip unavailable checks with info, got:\n%s", dump(all))
	}

	named, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckGSM}})
	if MaxSeverity(named) != SeverityError {
		t.Errorf("an explicitly requested check without its port must fail, got:\n%s", dump(named))
	}
}

func TestCheck_Cert(t *testing.T) {
	s, _ := newFixtureService(t)
	run := func(now time.Time, warnDays int) string {
		s.Now = func() time.Time { return now }
		f, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckCert}, WarnDays: warnDays})
		return MaxSeverity(f)
	}
	cfg, _ := s.Repo.Config()
	pemData, _ := s.Repo.Cert(cfg.Cert.RepoCertPath)
	notAfter := certNotAfter(t, pemData)

	if got := run(notAfter.AddDate(0, 0, -100), 30); got != SeverityInfo {
		t.Errorf("100 days before expiry: %s", got)
	}
	if got := run(notAfter.AddDate(0, 0, -10), 30); got != SeverityWarning {
		t.Errorf("10 days before expiry: %s", got)
	}
	if got := run(notAfter.AddDate(0, 0, 1), 30); got != SeverityError {
		t.Errorf("after expiry: %s", got)
	}

	if err := os.Remove(s.Repo.Root() + "/" + cfg.Cert.RepoCertPath); err != nil {
		t.Fatal(err)
	}
	if got := run(fixedNow, 30); got != SeverityError {
		t.Errorf("missing cert: %s", got)
	}
}

func TestCheck_Expiry(t *testing.T) {
	s, _ := newFixtureService(t)
	// tls-cert's keys expire 2026-03-01; my-app-secrets/api_key on 2026-06-15.
	cases := []struct {
		now  time.Time
		want string
	}{
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SeverityInfo},
		{time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), SeverityWarning},
		{time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), SeverityError},
	}
	for _, tc := range cases {
		s.Now = func() time.Time { return tc.now }
		f, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckExpiry}, WarnDays: 30})
		if got := MaxSeverity(f); got != tc.want {
			t.Errorf("at %s: %s, want %s\n%s", tc.now.Format("2006-01-02"), got, tc.want, dump(f))
		}
		if tc.want != SeverityInfo && f[0].Subject != "tls-cert/tls.crt" {
			t.Errorf("subject = %q", f[0].Subject)
		}
	}
}

func TestCheck_MetadataFindsDrift(t *testing.T) {
	s, _ := newFixtureService(t)
	m, _ := s.Repo.Metadata("my-app-secrets")

	// Manifest scope disagrees with metadata, and a key is only on one side.
	m.SealedSecret.Scope = core.ScopeNamespaceWide
	m.Keys = append(m.Keys, core.KeyMetadata{KeyName: "only_in_metadata", Source: core.SourceConfig{Kind: "gsm"},
		GSM: &core.GSMRef{SecretResource: "projects/p/secrets/x", Version: "1"}})
	if err := s.Repo.WriteMetadata(m); err != nil {
		t.Fatal(err)
	}

	f, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckMetadata}})
	errs := findingsBy(f, CheckMetadata, SeverityError)
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Subject+": "+e.Message)
	}
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "manifest scope is strict but metadata says namespace-wide") {
		t.Errorf("scope drift not reported:\n%s", joined)
	}
	if !strings.Contains(joined, "my-app-secrets/only_in_metadata: in metadata but not in the manifest") {
		t.Errorf("missing key not reported:\n%s", joined)
	}
}

func TestCheck_GSM(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)

	var progress []string
	f, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckGSM}, Progress: func(p string) { progress = append(progress, p) }})
	if MaxSeverity(f) != SeverityInfo {
		t.Errorf("seeded store:\n%s", dump(f))
	}
	if len(progress) < 2 || progress[0] != "gsm" {
		t.Errorf("progress = %v", progress)
	}

	// Point one key at a version that does not exist; break the store for another.
	m, _ := s.Repo.Metadata("my-app-secrets")
	m.Key("database_password").GSM.Version = "99"
	if err := s.Repo.WriteMetadata(m); err != nil {
		t.Fatal(err)
	}
	st.FailOn("AccessVersion", m.Key("api_key").GSM.SecretResource, errors.New("permission denied"))

	f, _ = s.Check(context.Background(), CheckInput{Checks: []string{CheckGSM}})
	if e := findingsBy(f, CheckGSM, SeverityError); len(e) != 1 || e[0].Subject != "my-app-secrets/database_password" {
		t.Errorf("errors:\n%s", dump(f))
	}
	if w := findingsBy(f, CheckGSM, SeverityWarning); len(w) != 1 || w[0].Subject != "my-app-secrets/api_key" {
		t.Errorf("warnings:\n%s", dump(f))
	}
}

func TestCheck_Cluster(t *testing.T) {
	s, _ := newFixtureService(t)
	cluster := clusterMatching(t, s)
	delete(cluster.secrets["my-app"+"/"+"my-app-secrets"], "api_key")
	cluster.secrets["my-app/my-app-secrets"]["stray"] = []byte("x")
	delete(cluster.secrets, "ingress-nginx/wildcard-tls")
	s.Cluster = cluster

	f, _ := s.Check(context.Background(), CheckInput{Checks: []string{CheckCluster}})
	e := findingsBy(f, CheckCluster, SeverityError)
	if len(e) != 1 || e[0].Subject != "my-app-secrets" || !strings.Contains(e[0].Message, "api_key") {
		t.Errorf("errors:\n%s", dump(f))
	}
	w := findingsBy(f, CheckCluster, SeverityWarning)
	if len(w) != 2 {
		t.Errorf("want a stray-key warning and an unreadable-secret warning:\n%s", dump(f))
	}
}

// clusterMatching builds a fake cluster holding exactly the keys metadata lists.
func clusterMatching(t *testing.T, s *Service) *fakeCluster {
	t.Helper()
	secrets, _ := s.Repo.AllMetadata()
	c := &fakeCluster{secrets: map[string]map[string][]byte{}}
	for _, m := range secrets {
		data := map[string][]byte{}
		for _, k := range m.Keys {
			data[k.KeyName] = []byte("v")
		}
		c.secrets[m.SealedSecret.Namespace+"/"+m.SealedSecret.Name] = data
	}
	return c
}

func dump(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString("  " + f.Severity + " " + f.Check + " " + f.Subject + ": " + f.Message + "\n")
	}
	return b.String()
}
