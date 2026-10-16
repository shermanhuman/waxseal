package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/computed"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/store"
)

const copySentinel = "sentinel-value-must-never-appear"

func ref(short, key string) *core.KeyRef { return &core.KeyRef{ShortName: short, KeyName: key} }

func copyFixture(t *testing.T) (*Service, context.Context) {
	t.Helper()
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	st.SetVersion("projects/waxseal-test-project/secrets/docker-registry-config", "2", []byte(copySentinel))
	return s, context.Background()
}

func TestAddKey_CopyAcrossNamespaces(t *testing.T) {
	s, ctx := copyFixture(t)
	st := s.Store

	res, err := s.AddKey(ctx, AddKeyInput{ShortName: "ghcr", Key: KeySpec{Name: ".dockerconfigjson", CopyFrom: ref("docker-registry", ".dockerconfigjson")},
		New: &NewSecret{Namespace: "support-cannon"}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("ghcr")
	k := m.Key(".dockerconfigjson")
	if k.GSM.SecretResource != "projects/waxseal-test-project/secrets/ghcr-dockerconfigjson" || k.GSM.Version != "1" {
		t.Errorf("gsm = %+v", k.GSM)
	}
	if k.CopiedFrom == nil || k.CopiedFrom.String() != "docker-registry/.dockerconfigjson@2" {
		t.Errorf("copiedFrom = %+v", k.CopiedFrom)
	}
	if k.Rotation == nil || k.Rotation.Mode != core.RotationExternal {
		t.Errorf("rotation not inherited: %+v", k.Rotation)
	}
	if m.SealedSecret.Type != "kubernetes.io/dockerconfigjson" || m.SealedSecret.Namespace != "support-cannon" {
		t.Errorf("sealedSecret = %+v (type is inherited from the source when not given)", m.SealedSecret)
	}
	if v, _ := st.AccessVersion(ctx, k.GSM.SecretResource, "1"); string(v) != copySentinel {
		t.Errorf("copied bytes differ")
	}
	ss, _ := s.Repo.Manifest(m)
	if ss.Spec.EncryptedData[".dockerconfigjson"] != "SEALED:support-cannon/ghcr/.dockerconfigjson="+copySentinel {
		t.Errorf("sealed = %s", ss.Spec.EncryptedData[".dockerconfigjson"])
	}
	src, _ := s.Repo.Metadata("docker-registry")
	if src.Key(".dockerconfigjson").CopiedFrom != nil || src.Key(".dockerconfigjson").GSM.Version != "2" {
		t.Error("the source must be untouched")
	}
	if c := res.Changes[0]; c.Kind != "gsm-version" || c.Source != "docker-registry/.dockerconfigjson@2" {
		t.Errorf("first change = %+v", c)
	}
	assertNoSentinel(t, res)

	// Overrides: rotation mode and expiry, and an explicit type.
	_, err = s.AddKey(ctx, AddKeyInput{ShortName: "ghcr2", Key: KeySpec{Name: "cfg", CopyFrom: ref("docker-registry", ".dockerconfigjson"),
		Mode: core.RotationStatic, ExpiresAt: "2027-01-01T00:00:00Z"}, New: &NewSecret{Namespace: "x", Type: "Opaque"}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("ghcr2")
	if k := m.Key("cfg"); k.Rotation.Mode != core.RotationStatic || k.Expiry.ExpiresAt != "2027-01-01T00:00:00Z" || m.SealedSecret.Type != "Opaque" {
		t.Errorf("overrides lost: %+v %+v %s", k.Rotation, k.Expiry, m.SealedSecret.Type)
	}
}

func TestAddKey_CopyInheritsDefinitionAndComputedPayload(t *testing.T) {
	s, ctx := copyFixture(t)
	_, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Value: []byte("pw1"),
		Template: &TemplateSpec{Template: "redis://:{{secret}}@{{host}}", Values: map[string]string{"host": "cache"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "other", Key: KeySpec{Name: "REDIS_URL", CopyFrom: ref("my-app-secrets", "conn")},
		New: &NewSecret{Namespace: "other"}}); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("other")
	k := m.Key("REDIS_URL")
	if k.Source.Kind != "computed" || k.Computed.Template != "redis://:{{secret}}@{{host}}" || k.Computed.GSM.Version != "1" {
		t.Errorf("computed = %+v", k.Computed)
	}
	data, _ := s.Store.AccessVersion(ctx, k.Computed.GSM.SecretResource, "1")
	if p, err := computed.ParsePayload(data); err != nil || p.Secret != "pw1" || p.Values["host"] != "cache" {
		t.Errorf("payload not copied verbatim: %+v %v", p, err)
	}
	ss, _ := s.Repo.Manifest(m)
	if !strings.HasSuffix(ss.Spec.EncryptedData["REDIS_URL"], "=redis://:pw1@cache") {
		t.Errorf("sealed = %s", ss.Spec.EncryptedData["REDIS_URL"])
	}

	// Expiry comes with the value: api_key expires 2026-06-15.
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "other", Key: KeySpec{Name: "API_KEY", CopyFrom: ref("my-app-secrets", "api_key")}}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("other")
	if e := m.Key("API_KEY").Expiry; e == nil || e.ExpiresAt != "2026-06-15T00:00:00Z" {
		t.Errorf("expiry = %+v", e)
	}
}

func TestAddKey_CopySources(t *testing.T) {
	s, ctx := copyFixture(t)
	add := func(from *core.KeyRef, name string) error {
		_, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: name, CopyFrom: from}})
		return err
	}

	// A retired source can still be copied.
	if _, err := s.Retire(RetireInput{ShortName: "docker-registry", Reason: "moved"}); err != nil {
		t.Fatal(err)
	}
	if err := add(ref("docker-registry", ".dockerconfigjson"), "revived"); err != nil {
		t.Errorf("retired source: %v", err)
	}

	cases := []struct {
		name string
		from *core.KeyRef
		want func(error) bool
	}{
		{"unregistered secret", ref("nope", "k"), func(err error) bool { return errors.Is(err, ErrNotRegistered) }},
		{"unknown key", ref("tls-cert", "nope"), func(err error) bool { return errors.Is(err, ErrKeyNotFound) }},
		{"derived key", ref("my-app-secrets", "DATABASE_URL"), func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "derived from other keys")
		}},
		{"empty ref", &core.KeyRef{}, func(err error) bool { return errors.As(err, new(*core.MissingInputError)) }},
	}
	for _, tc := range cases {
		if err := add(tc.from, "x-"+strings.ReplaceAll(tc.name, " ", "-")); !tc.want(err) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}

	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "y", CopyFrom: ref("tls-cert", "tls.key"),
		Template: &TemplateSpec{Template: "{{secret}}"}}}); err == nil {
		t.Error("--from-key with --template must be refused")
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "y", CopyFrom: ref("tls-cert", "tls.key"),
		Value: []byte("v")}}); err == nil {
		t.Error("--from-key with a value must be refused")
	}
}

func TestAddKey_CopyDryRun(t *testing.T) {
	s, ctx := copyFixture(t)
	before := s.Store.(interface{ Resources() []string }).Resources()
	res, err := s.AddKey(ctx, AddKeyInput{ShortName: "ghcr", Key: KeySpec{Name: "cfg", CopyFrom: ref("docker-registry", ".dockerconfigjson")},
		New: &NewSecret{Namespace: "ns"}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Store.(interface{ Resources() []string }).Resources(); !reflect.DeepEqual(got, before) {
		t.Errorf("dry run wrote to GSM: %v", got)
	}
	if _, err := s.Repo.Metadata("ghcr"); !core.IsNotFound(err) {
		t.Errorf("dry run wrote metadata: %v", err)
	}
	if res.Changes[0].Source != "docker-registry/.dockerconfigjson@2" {
		t.Errorf("changes = %+v", res.Changes)
	}

	// A source version missing from GSM fails a dry run too.
	bare, _ := newFixtureService(t)
	if _, err := bare.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "cfg", CopyFrom: ref("docker-registry", ".dockerconfigjson")}, DryRun: true}); !core.IsNotFound(err) {
		t.Errorf("missing source version: got %v", err)
	}
}

func TestSetKeyValue_FromKey(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "ghcr", Key: KeySpec{Name: "cfg", CopyFrom: ref("docker-registry", ".dockerconfigjson")},
		New: &NewSecret{Namespace: "ns"}}); err != nil {
		t.Fatal(err)
	}

	// The source moves on; Next lists the copy; check says it is behind.
	res, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "docker-registry", Key: ".dockerconfigjson", Value: []byte(copySentinel + "-2")})
	if err != nil {
		t.Fatal(err)
	}
	want := []CopyRef{{Source: core.KeyRef{ShortName: "docker-registry", KeyName: ".dockerconfigjson"}, Target: core.KeyRef{ShortName: "ghcr", KeyName: "cfg"}}}
	if !reflect.DeepEqual(res.Copies, want) {
		t.Errorf("copies = %+v", res.Copies)
	}
	if w := findingsBy(checkCopies(allMetadata(t, s)), CheckMetadata, SeverityWarning); len(w) != 1 || !strings.Contains(w[0].Message, "waxseal key set ghcr cfg --from-key docker-registry/.dockerconfigjson") {
		t.Errorf("findings = %s", dump(w))
	}

	// Re-copy: new version, provenance follows, check is quiet.
	res, err = s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "ghcr", Key: "cfg", CopyFrom: ref("docker-registry", ".dockerconfigjson")})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("ghcr")
	if k := m.Key("cfg"); k.GSM.Version != "2" || k.CopiedFrom.String() != "docker-registry/.dockerconfigjson@3" {
		t.Errorf("key = %+v %+v", k.GSM, k.CopiedFrom)
	}
	if v, _ := s.Store.AccessVersion(ctx, m.Key("cfg").GSM.SecretResource, "2"); string(v) != copySentinel+"-2" {
		t.Error("re-copied bytes differ")
	}
	if f := checkCopies(allMetadata(t, s)); len(f) != 0 {
		t.Errorf("in sync, got %s", dump(f))
	}
	assertNoSentinel(t, res)

	// Re-pointing replaces the whole provenance.
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "ghcr", Key: "cfg", CopyFrom: ref("tls-cert", "tls.key")}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("ghcr")
	if got := m.Key("cfg").CopiedFrom.String(); got != "tls-cert/tls.key@5" {
		t.Errorf("copiedFrom = %s", got)
	}
	if e := m.Key("cfg").Expiry; e == nil || e.ExpiresAt != "2026-03-01T00:00:00Z" {
		t.Errorf("the source's expiry should come with its value: %+v", e)
	}

	// Any other value change ends the copy, and says so.
	res, err = s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "ghcr", Key: "cfg", Value: []byte("typed")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detached) != 1 || res.Detached[0].Source.ShortName != "tls-cert" {
		t.Errorf("detached = %+v", res.Detached)
	}
	m, _ = s.Repo.Metadata("ghcr")
	if m.Key("cfg").CopiedFrom != nil {
		t.Error("copiedFrom should be cleared")
	}
	if got := s.copiesOf("tls-cert", "tls.key"); len(got) != 0 {
		t.Errorf("a detached key is not a copy: %+v", got)
	}

	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "ghcr", Key: "cfg", CopyFrom: ref("ghcr", "cfg")}); err == nil || !strings.Contains(err.Error(), "never in sync") {
		t.Error("copying a key from itself must be refused")
	}
}

func TestSetKeyValue_FromKeyKinds(t *testing.T) {
	s, ctx := copyFixture(t)
	for _, name := range []string{"a", "b"} {
		_, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: name, Value: []byte("secret-" + name),
			Template: &TemplateSpec{Template: name + "://{{secret}}"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	// computed → computed copies {{secret}} and keeps the target's template.
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "b", CopyFrom: ref("my-app-secrets", "a")}); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("my-app-secrets")
	data, _ := s.Store.AccessVersion(ctx, m.Key("b").Computed.GSM.SecretResource, m.Key("b").Computed.GSM.Version)
	if p, _ := computed.ParsePayload(data); p.Secret != "secret-a" || p.Computed != "b://secret-a" {
		t.Errorf("payload = %+v", p)
	}

	// Mixed kinds are refused, naming both keys, without the value.
	_, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "a", CopyFrom: ref("docker-registry", ".dockerconfigjson")})
	if err == nil || !strings.Contains(err.Error(), "docker-registry/.dockerconfigjson is a plain key and my-app-secrets/a is a computed key") {
		t.Errorf("mixed kinds: got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), copySentinel) {
		t.Error("error leaks the value")
	}
}

func TestRotate_CopiesAreListedAndRotatedCopiesDetach(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "token", Generator: &core.GeneratorConfig{Kind: core.GeneratorRandomHex}}}); err != nil {
		t.Fatal(err)
	}
	// Two generated keys, each copied under a different name.
	for src, dst := range map[string]string{"database_password": "DB_PASSWORD", "token": "TOKEN"} {
		if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "other", Key: KeySpec{Name: dst, CopyFrom: ref("my-app-secrets", src)},
			New: &NewSecret{Namespace: "other"}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range res.Copies {
		got[c.Source.KeyName] = c.Target.ShortName + "/" + c.Target.KeyName
	}
	if !reflect.DeepEqual(got, map[string]string{"database_password": "other/DB_PASSWORD", "token": "other/TOKEN"}) {
		t.Errorf("copies = %+v", res.Copies)
	}

	// Rotating a copy makes it independent.
	res, err = s.Rotate(ctx, RotateInput{ShortName: "other", Keys: []string{"TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detached) != 1 || res.Detached[0].Target.KeyName != "TOKEN" {
		t.Errorf("detached = %+v", res.Detached)
	}
	m, _ := s.Repo.Metadata("other")
	if m.Key("TOKEN").CopiedFrom != nil || m.Key("DB_PASSWORD").CopiedFrom == nil {
		t.Errorf("TOKEN should detach, DB_PASSWORD stays a copy")
	}
	if f := checkCopies(allMetadata(t, s)); len(f) != 1 || f[0].Subject != "other/DB_PASSWORD" {
		t.Errorf("only DB_PASSWORD is behind: %s", dump(f))
	}
	if c := s.copiesOf("my-app-secrets", "token"); len(c) != 0 {
		t.Errorf("token has no copies left: %+v", c)
	}
}

func TestCheck_CopiesAndSharedResources(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "other", Key: KeySpec{Name: "K", CopyFrom: ref("tls-cert", "tls.key")}, New: &NewSecret{Namespace: "o"}}); err != nil {
		t.Fatal(err)
	}
	if f := checkCopies(allMetadata(t, s)); len(f) != 0 {
		t.Errorf("in sync: %s", dump(f))
	}

	// The source key disappears: info, not a warning.
	tls, _ := s.Repo.Metadata("tls-cert")
	tls.Keys = tls.Keys[:1]
	if err := s.Repo.WriteMetadata(tls); err != nil {
		t.Fatal(err)
	}
	if f := checkCopies(allMetadata(t, s)); len(f) != 1 || f[0].Severity != SeverityInfo || !strings.Contains(f[0].Message, "no longer registered") {
		t.Errorf("removed source key: %s", dump(f))
	}

	// A retired source: nothing to compare.
	if _, err := s.Retire(RetireInput{ShortName: "tls-cert"}); err != nil {
		t.Fatal(err)
	}
	if f := checkCopies(allMetadata(t, s)); len(f) != 0 {
		t.Errorf("retired source: %s", dump(f))
	}

	// Two keys sharing one GSM secret: quiet at equal versions, a warning otherwise.
	m, _ := s.Repo.Metadata("other")
	shared := *m.Key("K").GSM
	m.Keys = append(m.Keys, core.KeyMetadata{KeyName: "K2", Source: core.SourceConfig{Kind: "gsm"}, GSM: &shared})
	if err := s.Repo.WriteMetadata(m); err != nil {
		t.Fatal(err)
	}
	if f := checkSharedResources(allMetadata(t, s)); len(f) != 0 {
		t.Errorf("same version: %s", dump(f))
	}
	m.Keys[1].GSM.Version = "2"
	if err := s.Repo.WriteMetadata(m); err != nil {
		t.Fatal(err)
	}
	f := checkSharedResources(allMetadata(t, s))
	if len(f) != 1 || f[0].Severity != SeverityWarning || !strings.Contains(f[0].Message, "other/K pins version 1, other/K2 pins version 2") {
		t.Errorf("drift: %s", dump(f))
	}
	all, _ := s.Check(ctx, CheckInput{Checks: []string{CheckMetadata}})
	if len(findingsBy(all, CheckMetadata, SeverityWarning)) == 0 {
		t.Error("check metadata must include the shared-resource warning")
	}
}

func allMetadata(t *testing.T, s *Service) []*core.SecretMetadata {
	t.Helper()
	secrets, errs := s.Repo.AllMetadata()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return secrets
}

func assertNoSentinel(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), copySentinel) {
		t.Errorf("result leaks the value: %s", b)
	}
}

func TestAddKey_CopyRotationOverrides(t *testing.T) {
	s, ctx := copyFixture(t)
	// generated → static drops the generator, as build does.
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "PW", CopyFrom: ref("my-app-secrets", "database_password"), Mode: core.RotationStatic},
		New: &NewSecret{Namespace: "o"}}); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Repo.Metadata("o")
	if r := m.Key("PW").Rotation; r.Mode != core.RotationStatic || r.Generator != nil {
		t.Errorf("rotation = %+v", r)
	}
	// external → generated has no generator to rotate with: refused, naming --rotation.
	_, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "K", CopyFrom: ref("tls-cert", "tls.key"), Mode: core.RotationGenerated}})
	if err == nil || !strings.Contains(err.Error(), "--rotation") || !strings.Contains(err.Error(), "waxseal key edit o K --rotation generated") {
		t.Errorf("got %v", err)
	}
	// --expires none clears the inherited expiry.
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "API", CopyFrom: ref("my-app-secrets", "api_key"), ClearExpiry: true}}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.Repo.Metadata("o")
	if m.Key("API").Expiry != nil {
		t.Errorf("expiry = %+v, want none", m.Key("API").Expiry)
	}
}

func TestRotate_DryRunDoesNotListACopyItDetaches(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "pw_copy", CopyFrom: ref("my-app-secrets", "database_password")}}); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		res, err := s.Rotate(ctx, RotateInput{ShortName: "my-app-secrets", DryRun: dry})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Copies) != 0 || len(res.Detached) != 1 {
			t.Errorf("dry=%v: copies %+v detached %+v", dry, res.Copies, res.Detached)
		}
	}
}

func TestUpdateComputed_ListsCopies(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Value: []byte("pw"),
		Template: &TemplateSpec{Template: "redis://:{{secret}}@{{host}}", Values: map[string]string{"host": "a"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "conn", CopyFrom: ref("my-app-secrets", "conn")}, New: &NewSecret{Namespace: "o"}}); err != nil {
		t.Fatal(err)
	}
	res, err := s.UpdateComputed(ctx, UpdateComputedInput{ShortName: "my-app-secrets", Key: "conn", Values: map[string]string{"host": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Copies) != 1 || res.Copies[0].Target.ShortName != "o" {
		t.Errorf("copies = %+v", res.Copies)
	}
}

func TestImport_KeepsACopyHoldingTheSameValueAndDetachesAChangedOne(t *testing.T) {
	s, ctx := copyFixture(t)
	for _, k := range []string{"tls.crt", "tls.key"} {
		if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: k, CopyFrom: ref("tls-cert", k)}, New: &NewSecret{Namespace: "o"}}); err != nil {
			t.Fatal(err)
		}
	}
	s.Cluster = &fakeCluster{secrets: map[string]map[string][]byte{"o/o": {
		"tls.crt": []byte("value-of-tls.crt"), // what was copied
		"tls.key": []byte("edited by hand"),
	}}}
	res, err := s.Import(ctx, ImportInput{ShortName: "o"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detached) != 1 || res.Detached[0].Target.KeyName != "tls.key" {
		t.Errorf("detached = %+v", res.Detached)
	}
	m, _ := s.Repo.Metadata("o")
	if m.Key("tls.crt").CopiedFrom == nil || m.Key("tls.key").CopiedFrom != nil {
		t.Errorf("crt %+v key %+v", m.Key("tls.crt").CopiedFrom, m.Key("tls.key").CopiedFrom)
	}
}

func TestAddKey_CopyOfGeneratedComputedKeyMadeStatic(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Generator: &core.GeneratorConfig{Kind: core.GeneratorRandomHex},
		Template: &TemplateSpec{Template: "redis://:{{secret}}@h"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "conn", CopyFrom: ref("my-app-secrets", "conn"), Mode: core.RotationStatic},
		New: &NewSecret{Namespace: "o"}}); err != nil {
		t.Fatal(err)
	}
	view, err := s.DescribeComputed(ctx, "o", "conn")
	if err != nil || view.Generated {
		t.Errorf("a static copy's payload must not carry a generator: %+v %v", view, err)
	}
	src, _ := s.DescribeComputed(ctx, "my-app-secrets", "conn")
	if !src.Generated {
		t.Error("the source's payload is untouched")
	}
}

func TestImport_SkippedComputedCopyKeepsProvenanceAndReadErrorsSurface(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "conn", Value: []byte("pw"),
		Template: &TemplateSpec{Template: "redis://:{{secret}}@h"}}}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct{ from, name string }{{"my-app-secrets/conn", "conn"}, {"tls-cert/tls.key", "tls.key"}} {
		short, key, _ := strings.Cut(k.from, "/")
		if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: k.name, CopyFrom: ref(short, key)}, New: &NewSecret{Namespace: "o"}}); err != nil {
			t.Fatal(err)
		}
	}
	// conn is skipped (not a connection string); tls.key is rewritten with its copied value.
	s.Cluster = &fakeCluster{secrets: map[string]map[string][]byte{"o/o": {"conn": []byte("not a url"), "tls.key": []byte("value-of-tls.key")}}}
	res, err := s.Import(ctx, ImportInput{ShortName: "o"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Detached) != 0 || len(res.Skipped) != 1 {
		t.Errorf("detached %+v skipped %+v", res.Detached, res.Skipped)
	}
	m, _ := s.Repo.Metadata("o")
	if m.Key("conn").CopiedFrom == nil || m.Key("tls.key").CopiedFrom == nil {
		t.Error("neither value changed; both stay copies")
	}

	// A GSM read failure is an error, not a cluster difference.
	st := s.Store.(*store.FakeStore)
	st.FailOn("AccessVersion", m.Key("tls.key").GSM.SecretResource, errBoom)
	if _, err := s.Import(ctx, ImportInput{ShortName: "o", DryRun: true}); !errors.Is(err, errBoom) {
		t.Errorf("got %v", err)
	}
}

func TestImport_ComputedConnectionStringCopy(t *testing.T) {
	s, ctx := copyFixture(t)
	const tmpl = "postgresql://app:{{secret}}@{{host}}:5432/app"
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "DB_URL", Value: []byte("pw1"),
		Template: &TemplateSpec{Template: tmpl, Values: map[string]string{"host": "db"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "o", Key: KeySpec{Name: "DB_URL", CopyFrom: ref("my-app-secrets", "DB_URL")}, New: &NewSecret{Namespace: "o"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cluster  string
		detached int
	}{
		{"postgresql://app:pw1@db:5432/app", 0}, // still the copied value
		{"postgresql://app:edited@db:5432/app", 1},
	} {
		s.Cluster = &fakeCluster{secrets: map[string]map[string][]byte{"o/o": {"DB_URL": []byte(tc.cluster)}}}
		res, err := s.Import(ctx, ImportInput{ShortName: "o", DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Detached) != tc.detached {
			t.Errorf("%s: detached %+v", tc.cluster, res.Detached)
		}
	}
}

func TestAddKey_RefusesAResourceAnotherKeyUses(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "a", Key: KeySpec{Name: "b-c", Value: []byte("v")}, New: &NewSecret{Namespace: "n"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Store.(*store.FakeStore).Resources()
	// a-b/c and a/b-c both map to projects/…/secrets/a-b-c.
	for _, spec := range []KeySpec{{Name: "c", Value: []byte("v")}, {Name: "c", CopyFrom: ref("a", "b-c")}} {
		_, err := s.AddKey(ctx, AddKeyInput{ShortName: "a-b", Key: spec, New: &NewSecret{Namespace: "n"}})
		if err == nil || !strings.Contains(err.Error(), "which a/b-c already uses") {
			t.Errorf("%+v: got %v", spec, err)
		}
	}
	if got := s.Store.(*store.FakeStore).Resources(); !reflect.DeepEqual(got, before) {
		t.Errorf("a refused add wrote to GSM: %v", got)
	}
}

func TestSetKeyValue_FromKeyRefusesCycles(t *testing.T) {
	s, ctx := copyFixture(t)
	for _, step := range [][2]string{{"b", "api_key"}, {"c", "b"}} {
		if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: step[0], CopyFrom: ref("my-app-secrets", step[1])}}); err != nil {
			t.Fatal(err)
		}
	}
	// b ← api_key and c ← b: copying b or c back into api_key would loop.
	for _, from := range []string{"b", "c", "api_key"} {
		_, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key", CopyFrom: ref("my-app-secrets", from)})
		if err == nil || !strings.Contains(err.Error(), "never in sync") {
			t.Errorf("from %s: got %v", from, err)
		}
	}
	// The acyclic direction is fine: c re-copies from api_key.
	if _, err := s.SetKeyValue(ctx, SetKeyValueInput{ShortName: "my-app-secrets", Key: "c", CopyFrom: ref("my-app-secrets", "api_key")}); err != nil {
		t.Errorf("acyclic re-point: %v", err)
	}
}

func TestNewResource_GuardsImportAndUnreadableMetadata(t *testing.T) {
	s, ctx := copyFixture(t)
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app", Key: KeySpec{Name: "secrets-zzz", Value: []byte("v")}, New: &NewSecret{Namespace: "n"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Store.(*store.FakeStore).Resources()

	// import: a new cluster key zzz in my-app-secrets maps to my-app-secrets-zzz too.
	s.Cluster = clusterMatching(t, s)
	s.Cluster.(*fakeCluster).secrets["my-app/my-app-secrets"]["zzz"] = []byte("x")
	if _, err := s.Import(ctx, ImportInput{ShortName: "my-app-secrets"}); err == nil || !strings.Contains(err.Error(), "which my-app/secrets-zzz already uses") {
		t.Errorf("import: got %v", err)
	}

	// A retired owner says so.
	if _, err := s.Retire(RetireInput{ShortName: "my-app"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "zzz", Value: []byte("v")}})
	if err == nil || !strings.Contains(err.Error(), "which my-app/secrets-zzz (retired) already uses") {
		t.Errorf("retired owner: got %v", err)
	}

	// An unreadable metadata file is an error, not a pass.
	if err := os.WriteFile(s.Repo.MetadataPath("my-app"), []byte("not: [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "zzz", Value: []byte("v")}}); err == nil || !strings.Contains(err.Error(), "cannot check that") {
		t.Errorf("unreadable metadata: got %v", err)
	}
	if got := s.Store.(*store.FakeStore).Resources(); !reflect.DeepEqual(got, before) {
		t.Errorf("a refused add or import wrote to GSM: %v", got)
	}
}
