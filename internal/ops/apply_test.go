package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
)

// keyAdd is the common mutation the transaction tests drive: a new plain
// key on my-app-secrets.
func keyAdd(name string) AddKeyInput {
	return AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: name, Value: []byte("hunter2")}}
}

func TestApply_DryRunTouchesNothing(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	before := st.Resources()
	metaBefore, _ := os.ReadFile(s.Repo.MetadataPath("my-app-secrets"))

	in := keyAdd("new_key")
	in.DryRun = true
	res, err := s.AddKey(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || len(res.Changes) != 3 {
		t.Errorf("dry-run result: %+v", res)
	}
	if got := st.Resources(); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Error("dry run wrote to GSM")
	}
	metaAfter, _ := os.ReadFile(s.Repo.MetadataPath("my-app-secrets"))
	if string(metaAfter) != string(metaBefore) {
		t.Error("dry run wrote metadata")
	}
}

// Bug 4 (edit's rollback): a failure after GSM writes must remove exactly
// the secrets this call created, and never a pre-existing one.
func TestApply_RollbackDeletesOnlyWhatItCreated(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	before := st.Resources()

	blockManifestWrites(t, s)

	_, err := s.AddKey(context.Background(), keyAdd("new_key"))
	if err == nil {
		t.Fatal("expected the manifest write to fail")
	}
	if got := st.Resources(); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Errorf("store after rollback = %v, want the original %v", got, before)
	}
	if got, _ := s.Repo.Metadata("my-app-secrets"); got.Key("new_key") != nil {
		t.Error("metadata must not record a key whose GSM secret was rolled back")
	}
}

// A version added to a pre-existing secret cannot be rolled back; the
// caller is told exactly which versions were created.
func TestApply_UnrecordedVersionIsReported(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	m, _ := s.Repo.Metadata("my-app-secrets")
	blockManifestWrites(t, s)

	_, err := s.SetKeyValue(context.Background(), SetKeyValueInput{ShortName: "my-app-secrets", Key: "api_key", Value: []byte("new")})
	var unrecorded *UnrecordedVersionError
	if !errors.As(err, &unrecorded) {
		t.Fatalf("got %v, want UnrecordedVersionError", err)
	}
	resource := m.Key("api_key").GSM.SecretResource
	if unrecorded.Versions[resource] != "2" {
		t.Errorf("reported versions = %v, want %s -> 2", unrecorded.Versions, resource)
	}
	if got, _ := s.Repo.Metadata("my-app-secrets"); got.Key("api_key").GSM.Version != "1" {
		t.Error("metadata must still point at the old version")
	}
}

// Sealing happens before any write, so a kubeseal failure leaves GSM alone.
func TestApply_SealFailureWritesNothing(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	before := st.Resources()
	s.Sealer = &seal.FakeSealer{Prefix: "SEALED:", FailKeys: map[string]error{"new_key": errors.New("cert expired")}}

	_, err := s.AddKey(context.Background(), keyAdd("new_key"))
	if err == nil || !strings.Contains(err.Error(), "cert expired") {
		t.Fatalf("got %v", err)
	}
	if got := st.Resources(); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Error("a sealing failure must not create GSM secrets")
	}
}

func TestApply_GSMFailureRollsBackEarlierCreates(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	before := st.Resources()
	// Two new keys; the second one's GSM create fails.
	st.FailOn("CreateSecret", s.gsmResource("my-app-secrets", "second"), errBoom)

	m, _ := s.Repo.Metadata("my-app-secrets")
	var writes []keyWrite
	for _, name := range []string{"first", "second"} {
		meta, w, err := KeySpec{Name: name, Value: []byte("v")}.build(s.gsmResource("my-app-secrets", name))
		if err != nil {
			t.Fatal(err)
		}
		m.Keys = append(m.Keys, meta)
		w.ref = m.Keys[len(m.Keys)-1].GSM
		writes = append(writes, w)
	}
	if _, err := s.apply(context.Background(), m, writes, false, false); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
	if got := st.Resources(); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Errorf("store = %v, want the first key's secret rolled back", got)
	}
}

// Bug 6: nothing an operation returns may contain a secret value.
func TestResults_NeverContainSecrets(t *testing.T) {
	s, st := newFixtureService(t)
	seedStore(t, s, st)
	const plaintext = "hunter2-very-secret"
	s.Cluster = clusterMatching(t, s)

	var results []any
	r1, err := s.AddKey(context.Background(), AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "pw", Value: []byte(plaintext)}})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.SetKeyValue(context.Background(), SetKeyValueInput{ShortName: "my-app-secrets", Key: "pw", Value: []byte(plaintext + "2")})
	if err != nil {
		t.Fatal(err)
	}
	r3, err := s.AddKey(context.Background(), AddKeyInput{ShortName: "my-app-secrets", Key: KeySpec{Name: "url",
		Value: []byte(plaintext), Template: &TemplateSpec{Template: "postgres://u:{{secret}}@{{host}}/db", Values: map[string]string{"host": "h"}}}})
	if err != nil {
		t.Fatal(err)
	}
	r4, err := s.DescribeComputed(context.Background(), "my-app-secrets", "url")
	if err != nil {
		t.Fatal(err)
	}
	r5, err := s.Show("my-app-secrets")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := s.Check(context.Background(), CheckInput{})
	results = append(results, r1, r2, r3, r4, r5, f)

	for i, r := range results {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), plaintext) {
			t.Errorf("result %d leaks the secret: %s", i, b)
		}
	}
}

func TestBuildManifest_KeepsUserAnnotationsAndLabels(t *testing.T) {
	m := &core.SecretMetadata{SealedSecret: core.SealedSecretRef{Name: "app", Namespace: "prod", Scope: core.ScopeNamespaceWide}}
	existing := seal.NewSealedSecret("app", "prod", core.ScopeStrict, "Opaque", map[string]string{"a": "OLD-A", "b": "OLD-B"})
	existing.Metadata.Annotations = map[string]string{"argocd.argoproj.io/sync-wave": "1", seal.AnnotationScope: "strict"}
	existing.Metadata.Labels = map[string]string{"team": "platform"}

	ss := buildManifest(m, existing, map[string]string{"a": "NEW-A"}, false)
	if ss.Spec.EncryptedData["a"] != "NEW-A" || ss.Spec.EncryptedData["b"] != "OLD-B" {
		t.Errorf("merge: %v", ss.Spec.EncryptedData)
	}
	if ss.GetScope() != core.ScopeNamespaceWide {
		t.Errorf("scope must come from metadata, got %s", ss.GetScope())
	}
	if _, stale := ss.Metadata.Annotations[seal.AnnotationScope]; stale {
		t.Error("stale scope annotation from the old manifest must not survive")
	}
	if ss.Metadata.Annotations["argocd.argoproj.io/sync-wave"] != "1" || ss.Metadata.Labels["team"] != "platform" {
		t.Errorf("user metadata lost: %+v", ss.Metadata)
	}

	full := buildManifest(m, existing, map[string]string{"a": "NEW-A"}, true)
	if _, ok := full.Spec.EncryptedData["b"]; ok {
		t.Error("a full reseal must drop keys that are no longer in metadata")
	}
}

// blockManifestWrites makes the manifest's directory read-only, so the
// existing manifest can still be read but nothing new can be staged there.
// The failure therefore happens after GSM writes, which is what the
// rollback tests need to exercise.
func blockManifestWrites(t *testing.T, s *Service) {
	t.Helper()
	m, err := s.Repo.Metadata("my-app-secrets")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, _ := s.Repo.ManifestPath(m)
	dir := filepath.Dir(manifestPath)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		f.Close()
		os.Remove(f.Name())
		t.Skip("directory permissions are not enforced here (running as root?)")
	}
}
