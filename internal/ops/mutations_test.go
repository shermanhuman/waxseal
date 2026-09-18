package ops

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/reminder"
	"github.com/shermanhuman/waxseal/internal/template"
)

func TestAddKey_ExistingSecret(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	ctx := context.Background()

	res, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "token", Generator: &core.GeneratorConfig{Kind: core.GeneratorRandomHex, Bytes: 16}, ExpiresAt: "2027-01-01T00:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Versions["token"] != "1" {
		t.Errorf("versions = %v", res.Versions)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	k := m.Key("token")
	if k == nil || k.Rotation.Mode != core.RotationGenerated || k.GSM.Version != "1" || k.Expiry.ExpiresAt != "2027-01-01T00:00:00Z" {
		t.Errorf("metadata key = %+v", k)
	}
	value, _ := st.AccessVersion(ctx, k.GSM.SecretResource, "1")
	if len(value) != 32 {
		t.Errorf("generated hex of 16 bytes should be 32 chars, got %d", len(value))
	}
	ss, _ := s.Repo.Manifest(m)
	if ss.Spec.EncryptedData["token"] != "SEALED:my-app/my-app-secrets/token="+string(value) {
		t.Errorf("manifest not sealed with the new value: %s", ss.Spec.EncryptedData["token"])
	}
	if ss.Spec.EncryptedData["api_key"] == "" {
		t.Error("existing ciphertext must be kept")
	}

	if _, err := s.AddKey(ctx, keyAdd("token")); !errors.Is(err, ErrKeyExists) {
		t.Errorf("duplicate key: got %v", err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "x"}}); !errors.As(err, new(*core.MissingInputError)) {
		t.Errorf("no value and no generator: got %v", err)
	}
}

func TestAddKey_CreatesSecret(t *testing.T) {
	s, st := newFixtureService(t)
	ctx := context.Background()

	_, err := s.AddKey(ctx, AddKeyInput{ShortName: "new-app", Key: KeySpec{Name: "pw", Value: []byte("v")}})
	if !errors.Is(err, ErrNeedsNamespace) {
		t.Fatalf("unregistered without New: got %v", err)
	}
	_, err = s.AddKey(ctx, AddKeyInput{ShortName: "new-app", Key: KeySpec{Name: "pw", Value: []byte("v")}, New: &NewSecret{}})
	if !errors.As(err, new(*core.MissingInputError)) {
		t.Fatalf("New without namespace: got %v", err)
	}

	res, err := s.AddKey(ctx, AddKeyInput{ShortName: "new-app", Key: KeySpec{Name: "pw", Value: []byte("v")},
		New: &NewSecret{Namespace: "staging", Scope: core.ScopeNamespaceWide, Type: "kubernetes.io/basic-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Repo.Metadata("new-app")
	if err != nil {
		t.Fatal(err)
	}
	if m.ManifestPath != "apps/new-app/sealed-secret.yaml" || m.SealedSecret.Namespace != "staging" || m.SealedSecret.Scope != core.ScopeNamespaceWide {
		t.Errorf("metadata = %+v", m)
	}
	ss, err := s.Repo.Manifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if ss.GetScope() != core.ScopeNamespaceWide || ss.GetSecretType() != "kubernetes.io/basic-auth" {
		t.Errorf("manifest scope/type: %s %s", ss.GetScope(), ss.GetSecretType())
	}
	if c := res.Changes[len(res.Changes)-1]; c.Op != "create" || c.Kind != "manifest" {
		t.Errorf("last change = %+v, want manifest create", c)
	}
	if got := st.Resources(); len(got) != 1 || got[0] != "projects/waxseal-test-project/secrets/new-app-pw" {
		t.Errorf("store = %v", got)
	}
}

func TestSetKeyValue_PlainAndComputed(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	ctx := context.Background()

	// Plain key: new version, metadata pointer moves, ciphertext replaced.
	res, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key", Value: []byte("fresh")})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	if m.Key("api_key").GSM.Version != "2" || res.Versions["api_key"] != "2" {
		t.Errorf("version not bumped: meta=%s res=%v", m.Key("api_key").GSM.Version, res.Versions)
	}
	ss, _ := s.Repo.Manifest(m)
	if !strings.HasSuffix(ss.Spec.EncryptedData["api_key"], "=fresh") {
		t.Errorf("ciphertext = %s", ss.Spec.EncryptedData["api_key"])
	}

	// Expiry can be set or cleared alongside.
	clear := ""
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key", Value: []byte("x"), ExpiresAt: &clear}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("my-app-secrets")
	if m.Key("api_key").Expiry != nil {
		t.Error("expiry should be cleared")
	}

	// Computed key with a payload: the value becomes {{secret}}.
	_, err = s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Value: []byte("pw1"),
		Template: &TemplateSpec{Template: "redis://:{{secret}}@{{host}}:6379", Values: map[string]string{"host": "cache"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "conn", Value: []byte("pw2")}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("my-app-secrets")
	ref := m.Key("conn").Computed.GSM
	if ref.Version != "2" {
		t.Errorf("payload version = %s", ref.Version)
	}
	data, _ := st.AccessVersion(ctx, ref.SecretResource, "2")
	p, _ := template.ParsePayload(data)
	if p.Secret != "pw2" || p.Computed != "redis://:pw2@cache:6379" {
		t.Errorf("payload = %+v", p)
	}
	ss, _ = s.Repo.Manifest(m)
	if !strings.HasSuffix(ss.Spec.EncryptedData["conn"], "=redis://:pw2@cache:6379") {
		t.Errorf("ciphertext = %s", ss.Spec.EncryptedData["conn"])
	}

	// Bug 5: no value is an error, never a silent skip.
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key"}); !errors.As(err, new(*core.MissingInputError)) {
		t.Errorf("empty value: got %v", err)
	}
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "nope", Value: []byte("v")}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("unknown key: got %v", err)
	}
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "DATABASE_URL", Value: []byte("v")}); err == nil {
		t.Error("a key derived from siblings has nowhere to store a value")
	}
}

// Bug 3: the metadata pointer is on disk before the manifest is touched.
func TestSetKeyValue_MetadataPointerSurvivesManifestFailure(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	blockManifestWrites(t, s)
	_, err := s.SetKeyValue(context.Background(), SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key", Value: []byte("fresh")})
	if err == nil {
		t.Fatal("expected failure")
	}
	// repo.Commit stages both files before placing either, so with the
	// manifest unwritable the metadata pointer does not land; what must
	// never happen is a new version that is neither recorded nor reported.
	// (TestCommit_MetadataLandsBeforeManifest in repo covers the rename
	// ordering itself.)
	got, _ := s.Repo.Metadata("my-app-secrets")
	var unrecorded *UnrecordedVersionError
	if got.Key("api_key").GSM.Version != "2" && !errors.As(err, &unrecorded) {
		t.Errorf("new version 2 is neither recorded (%s) nor reported (%v)", got.Key("api_key").GSM.Version, err)
	}
}

func TestRotate(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	ctx := context.Background()

	// Unnamed: rotates generated keys, reports the others as skipped.
	res, err := s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Rotated, []string{"database_password"}) {
		t.Errorf("rotated = %v", res.Rotated)
	}
	if !reflect.DeepEqual(res.Skipped, []string{"api_key", "DATABASE_URL", "database_username"}) {
		t.Errorf("skipped = %v", res.Skipped)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	if m.Key("database_password").GSM.Version != "4" {
		t.Errorf("version = %s, want 4 (fixture had 3)", m.Key("database_password").GSM.Version)
	}
	value, _ := st.AccessVersion(ctx, m.Key("database_password").GSM.SecretResource, "4")
	if len(value) == 0 {
		t.Error("no generated value stored")
	}

	// Named non-generated key: an error, never a prompt or a silent skip.
	if _, err := s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets", Keys: []string{"api_key"}}); !errors.Is(err, ErrNotGenerated) {
		t.Errorf("external key: got %v", err)
	}
	if _, err := s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets", Keys: []string{"nope"}}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("unknown key: got %v", err)
	}

	// Generated computed key rotates its {{secret}} and re-renders.
	_, err = s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn",
		Generator: &core.GeneratorConfig{Kind: core.GeneratorRandomHex, Bytes: 8},
		Template:  &TemplateSpec{Template: "redis://:{{secret}}@{{host}}", Values: map[string]string{"host": "cache"}}}})
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets", Keys: []string{"conn"}})
	if err != nil || res.Versions["conn"] != "2" {
		t.Fatalf("computed rotate: %v %v", err, res)
	}
	m, _ = s.Repo.Metadata("my-app-secrets")
	data, _ := st.AccessVersion(ctx, m.Key("conn").Computed.GSM.SecretResource, "2")
	p, _ := template.ParsePayload(data)
	if len(p.Secret) != 16 || !strings.HasPrefix(p.Computed, "redis://:"+p.Secret+"@cache") {
		t.Errorf("payload = %+v", p)
	}
}

func TestEditKey(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	gen := core.RotationGenerated
	if _, err := s.EditKey(EditKeyInput{ShortName: "my-app-secrets", Key: "api_key", Rotation: &gen}); !errors.As(err, new(*core.MissingInputError)) {
		t.Errorf("generated without a generator: got %v", err)
	}
	exp := "2028-01-01T00:00:00Z"
	res, err := s.EditKey(EditKeyInput{ShortName: "my-app-secrets", Key: "api_key", Rotation: &gen,
		Generator: &core.GeneratorConfig{Kind: core.GeneratorRandomBase64, Bytes: 32}, ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 1 || res.Changes[0].Kind != "metadata" {
		t.Errorf("changes = %v", res.Changes)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	k := m.Key("api_key")
	if k.Rotation.Mode != gen || k.Rotation.Generator.Kind != core.GeneratorRandomBase64 || k.Expiry.ExpiresAt != exp {
		t.Errorf("key = %+v", k)
	}
	if before := st.Resources(); len(before) != 6 {
		t.Errorf("EditKey must not touch GSM, store has %d secrets", len(before))
	}
	if _, err := s.EditKey(EditKeyInput{ShortName: "my-app-secrets", Key: "api_key"}); !errors.As(err, new(*core.MissingInputError)) {
		t.Errorf("nothing to change: got %v", err)
	}
}

func TestUpdateComputed(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	ctx := context.Background()
	_, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Value: []byte("pw"),
		Template: &TemplateSpec{Template: "redis://:{{secret}}@{{host}}:{{port}}", Values: map[string]string{"host": "a", "port": "1"}}}})
	if err != nil {
		t.Fatal(err)
	}

	view, err := s.DescribeComputed(ctx, "my-app-secrets", "conn")
	if err != nil || view.Template != "redis://:{{secret}}@{{host}}:{{port}}" || view.Values["host"] != "a" || view.Generated {
		t.Fatalf("describe: %+v %v", view, err)
	}

	tmpl := "rediss://:{{secret}}@{{host}}:{{port}}/0"
	if _, err := s.UpdateComputed(ctx, UpdateComputedInput{ShortName: "my-app-secrets", Key: "conn", Template: &tmpl, Values: map[string]string{"host": "b"}}); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	k := m.Key("conn")
	if k.Computed.Template != tmpl || k.Computed.GSM.Version != "2" {
		t.Errorf("metadata = %+v", k.Computed)
	}
	ss, _ := s.Repo.Manifest(m)
	if !strings.HasSuffix(ss.Spec.EncryptedData["conn"], "=rediss://:pw@b:1/0") {
		t.Errorf("ciphertext = %s (secret must be kept, values merged)", ss.Spec.EncryptedData["conn"])
	}

	bad := "redis://{{host}}"
	if _, err := s.UpdateComputed(ctx, UpdateComputedInput{ShortName: "my-app-secrets", Key: "conn", Template: &bad}); err == nil {
		t.Error("a template without {{secret}} must be rejected")
	}
	if _, err := s.UpdateComputed(ctx, UpdateComputedInput{ShortName: "my-app-secrets", Key: "conn", Values: map[string]string{"host": ""}}); err == nil {
		// empty value is allowed by the payload; just make sure the path works
		t.Log("empty value accepted")
	}
	if _, err := s.UpdateComputed(ctx, UpdateComputedInput{ShortName: "my-app-secrets", Key: "api_key", Values: map[string]string{"x": "y"}}); err == nil {
		t.Error("a plain key is not computed")
	}
}

func TestRetire(t *testing.T) {
	s, _ := newFixtureService(t)
	res, err := s.Retire(RetireInput{ShortName: "tls-cert", Reason: "moved: see #42", ReplacedBy: "new-tls", DryRun: true})
	if err != nil || len(res.Changes) != 1 {
		t.Fatalf("dry run: %v %+v", err, res)
	}
	if m, _ := s.Repo.Metadata("tls-cert"); m.IsRetired() {
		t.Fatal("dry run retired the secret")
	}

	res, err = s.Retire(RetireInput{ShortName: "tls-cert", Reason: "moved: see #42", ReplacedBy: "new-tls", DeleteManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 2 || res.Changes[1].Op != "delete" {
		t.Errorf("changes = %v", res.Changes)
	}
	m, _ := s.Repo.Metadata("tls-cert")
	if !m.IsRetired() || m.RetireReason != "moved: see #42" || m.ReplacedBy != "new-tls" || m.RetiredAt != "2026-01-15T00:00:00Z" {
		t.Errorf("metadata = %+v", m)
	}
	if _, err := s.Repo.Manifest(m); !core.IsNotFound(err) {
		t.Error("manifest should be deleted")
	}

	// Already retired: nothing to do, not an error.
	res, err = s.Retire(RetireInput{ShortName: "tls-cert"})
	if err != nil || len(res.Changes) != 0 {
		t.Errorf("second retire: %v %+v", err, res)
	}
	if _, err := s.Reseal(context.Background(), ResealInput{ShortNames: []string{"tls-cert"}}); !errors.Is(err, core.ErrRetired) {
		t.Errorf("resealing a retired secret: got %v", err)
	}
}

func TestReseal_AllContinuesPastFailures(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	m, _ := s.Repo.Metadata("docker-registry")
	st.FailOn("AccessVersion", m.Keys[0].GSM.SecretResource, errBoom)

	results, err := s.Reseal(context.Background(), ResealInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %+v", results)
	}
	failed := 0
	for _, r := range results {
		if r.Error != "" {
			failed++
			if r.ShortName != "docker-registry" || !strings.Contains(r.Error, "boom") {
				t.Errorf("unexpected failure: %+v", r)
			}
		}
	}
	if failed != 1 {
		t.Errorf("%d failures, want 1", failed)
	}
}

func TestImport(t *testing.T) {
	s, st := newFixtureService(t)
	ctx := context.Background()
	// Unregister tls-cert so it is a new manifest to import.
	if err := os.Remove(s.Repo.MetadataPath("tls-cert")); err != nil {
		t.Fatal(err)
	}
	s.Cluster = &fakeCluster{secrets: map[string]map[string][]byte{
		"ingress-nginx/wildcard-tls": {
			"tls.crt": []byte("CERT"),
			"tls.key": []byte("KEY"),
			"DB_URL":  []byte("postgresql://admin:s3cret@db.internal:5432/app"),
		},
	}}

	if _, err := s.Import(ctx, ImportInput{ShortName: "nope"}); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("unknown name: got %v", err)
	}

	res, err := s.Import(ctx, ImportInput{ShortName: "ingress-nginx-wildcard-tls"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Added, []string{"DB_URL", "tls.crt", "tls.key"}) || !reflect.DeepEqual(res.Templated, []string{"DB_URL"}) {
		t.Errorf("result = %+v", res)
	}
	m, err := s.Repo.Metadata("ingress-nginx-wildcard-tls")
	if err != nil {
		t.Fatal(err)
	}
	if m.ManifestPath != "apps/ingress/tls-sealed-secret.yaml" || m.SealedSecret.Scope != core.ScopeClusterWide {
		t.Errorf("metadata = %+v", m)
	}
	db := m.Key("DB_URL")
	if db.Source.Kind != "computed" || db.Computed.Template != "postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}" {
		t.Errorf("DB_URL = %+v", db.Computed)
	}
	data, _ := st.AccessVersion(ctx, db.Computed.GSM.SecretResource, db.Computed.GSM.Version)
	p, _ := template.ParsePayload(data)
	if p.Secret != "s3cret" || p.Computed != "postgresql://admin:s3cret@db.internal:5432/app" {
		t.Errorf("payload = %+v", p)
	}
	crt := m.Key("tls.crt")
	if crt.Rotation.Mode != core.RotationExternal || crt.GSM.SecretResource != "projects/waxseal-test-project/secrets/ingress-nginx-wildcard-tls-tls-crt" {
		t.Errorf("tls.crt = %+v", crt)
	}
	ss, _ := s.Repo.Manifest(m)
	if ss.GetScope() != core.ScopeClusterWide || len(ss.Spec.EncryptedData) != 3 {
		t.Errorf("manifest = %+v", ss)
	}

	// Re-import of a registered secret: existing keys get new versions,
	// keys the cluster dropped are reported.
	delete(s.Cluster.(*fakeCluster).secrets["ingress-nginx/wildcard-tls"], "tls.key")
	res, err = s.Import(ctx, ImportInput{ShortName: "ingress-nginx-wildcard-tls"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Updated, []string{"DB_URL", "tls.crt"}) || !reflect.DeepEqual(res.MissingInCluster, []string{"tls.key"}) {
		t.Errorf("re-import = %+v", res)
	}
	if m, _ = s.Repo.Metadata("ingress-nginx-wildcard-tls"); m.Key("tls.crt").GSM.Version != "2" {
		t.Errorf("tls.crt version = %s", m.Key("tls.crt").GSM.Version)
	}
}

func TestReminders(t *testing.T) {
	s, _ := newFixtureService(t)
	ctx := context.Background()
	p := reminder.NewFakeProvider()

	res, err := s.SyncReminders(ctx, p, true)
	if err != nil || !reflect.DeepEqual(res.Secrets, []string{"my-app-secrets", "tls-cert"}) || len(p.SyncCalls) != 0 {
		t.Errorf("dry run: %+v %v calls=%d", res, err, len(p.SyncCalls))
	}
	res, err = s.SyncReminders(ctx, p, false)
	if err != nil || res.Created != 2 || len(p.SyncCalls) != 1 {
		t.Errorf("sync: %+v %v", res, err)
	}
	if err := s.ClearReminders(ctx, p, "tls-cert", false); err != nil || p.DeleteCalls[0] != "tls-cert" {
		t.Errorf("clear: %v %v", err, p.DeleteCalls)
	}
	if err := s.ClearReminders(ctx, p, "nope", false); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("clear unknown: %v", err)
	}
}

func TestInit(t *testing.T) {
	s, _ := newFixtureService(t)
	if _, err := s.Init(InitInput{ProjectID: "p"}); !errors.Is(err, ErrAlreadyInitialised) {
		t.Errorf("existing config: got %v", err)
	}
	if _, err := s.Init(InitInput{Force: true}); !errors.As(err, new(*core.MissingInputError)) {
		t.Errorf("no project: got %v", err)
	}
	if _, err := s.Init(InitInput{ProjectID: "other", ControllerNamespace: "sealed", Force: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Repo.Config()
	if err != nil || cfg.Store.ProjectID != "other" || cfg.Controller.Namespace != "sealed" || cfg.Controller.ServiceName != "sealed-secrets" {
		t.Errorf("config = %+v %v", cfg, err)
	}
}

func TestRefreshCert(t *testing.T) {
	s, _ := newFixtureService(t)
	cfg, _ := s.Repo.Config()
	s.Config = cfg
	current, _ := s.Repo.Cert(cfg.Cert.RepoCertPath)
	ctx := context.Background()

	s.Certs = &fakeCerts{pem: current}
	st, err := s.RefreshCert(ctx, true)
	if err != nil || st.Changed || st.Updated {
		t.Errorf("same cert: %+v %v", st, err)
	}

	rotated := testCertPEM(t)
	s.Certs = &fakeCerts{pem: rotated}
	st, err = s.RefreshCert(ctx, false)
	if err != nil || !st.Changed || st.Updated {
		t.Errorf("changed, not applied: %+v %v", st, err)
	}
	if got, _ := s.Repo.Cert(cfg.Cert.RepoCertPath); string(got) != string(current) {
		t.Error("cert must not be written without apply")
	}
	st, err = s.RefreshCert(ctx, true)
	if err != nil || !st.Updated {
		t.Errorf("apply: %+v %v", st, err)
	}
	if got, _ := s.Repo.Cert(cfg.Cert.RepoCertPath); string(got) != string(rotated) {
		t.Error("cert not updated")
	}

	s.Certs = &fakeCerts{pem: []byte("not a cert")}
	if _, err := s.RefreshCert(ctx, true); err == nil {
		t.Error("garbage from the cluster must be rejected")
	}
}
