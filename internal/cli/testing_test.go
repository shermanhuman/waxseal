package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/reminder"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// fixedNow is inside the fixture cert's validity and before every fixture
// expiry.
var fixedNow = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

type testApp struct {
	*App
	Store     *store.FakeStore
	Cluster   *fakeCluster
	Prompter  *ui.ScriptedPrompter
	Reminders *reminder.FakeProvider
	Out, Err  bytes.Buffer
	tty       bool
}

type fakeCerts struct{ pem []byte }

func (f *fakeCerts) FetchCert(context.Context, string, string) ([]byte, error) { return f.pem, nil }

type fakeCluster struct {
	secrets map[string]map[string][]byte
}

func (f *fakeCluster) GetSecret(_ context.Context, namespace, name string) (map[string][]byte, error) {
	if data, ok := f.secrets[namespace+"/"+name]; ok {
		return data, nil
	}
	return nil, core.WrapNotFound("secret "+namespace+"/"+name, nil)
}

// newTestApp builds an App over a copy of testdata/infra-repo with every
// port faked. Set tty to simulate a terminal (prompts then come from the
// scripted prompter).
func newTestApp(t *testing.T, tty bool) *testApp {
	t.Helper()
	dir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "testdata", "infra-repo"), dir)

	ta := &testApp{
		Store:    store.NewFakeStore(),
		Cluster:  &fakeCluster{secrets: map[string]map[string][]byte{}},
		Prompter: &ui.ScriptedPrompter{},
		tty:      tty,
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "keys", "pub-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ta.Reminders = reminder.NewFakeProvider()
	ta.App = &App{
		Stdin:  &bytes.Buffer{},
		Stdout: &ta.Out,
		Stderr: &ta.Err,
		Getenv: func(string) string { return "" },
		IsTTY:  func(any) bool { return ta.tty },
		Now:    func() time.Time { return fixedNow },
		NewStore: func(context.Context, string) (store.Store, func(), error) {
			return ta.Store, func() {}, nil
		},
		NewSealer: func(string) seal.Sealer { return seal.NewFakeSealer() },
		Cluster:   ta.Cluster,
		Certs:     &fakeCerts{pem: certPEM},
		Gcloud:    &gcp.Client{},
		NewReminders: func(context.Context, *config.RemindersConfig) (reminder.Provider, error) {
			return ta.Reminders, nil
		},
		Prompter: ta.Prompter,
		LookPath: func(string) error { return nil },
		CheckADC: func(context.Context) error { return nil },
	}
	ta.Flags.Repo = dir
	return ta
}

// run executes the CLI in-process and returns stdout, stderr and the exit code.
func (ta *testApp) run(args ...string) (stdout, stderr string, code int) {
	ta.Out.Reset()
	ta.Err.Reset()
	ta.Flags = GlobalFlags{Repo: ta.Flags.Repo}
	ta.cfg, ta.repo, ta.st = nil, nil, nil
	code = Main(context.Background(), ta.App, args)
	return ta.Out.String(), ta.Err.String(), code
}

// seedStore puts every GSM version the fixture references into the fake.
func (ta *testApp) seedStore(t *testing.T) {
	t.Helper()
	secrets, errs := ta.Repo().AllMetadata()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, m := range secrets {
		data := map[string][]byte{}
		for _, k := range m.Keys {
			if ref := k.ActiveRef(); ref != nil {
				ta.Store.SetVersion(ref.SecretResource, ref.Version, []byte("value-of-"+k.KeyName))
			}
			data[k.KeyName] = []byte("v")
		}
		ta.Cluster.secrets[m.SealedSecret.Namespace+"/"+m.SealedSecret.Name] = data
	}
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

// Repo returns the fixture repo, failing loudly on error.
func (ta *testApp) Repo() *repo.Repo {
	r, err := ta.App.Repo()
	if err != nil {
		panic(err)
	}
	return r
}

var _ ops.Cluster = (*fakeCluster)(nil)
var errBoom = errors.New("boom")
