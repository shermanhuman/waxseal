package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/reminder"
	"github.com/shermanhuman/waxseal/internal/testutil"
)

func TestKeyAdd_NewSecretFromFlagsAndStdin(t *testing.T) {
	ta := newTestApp(t, false)
	ta.Stdin = bytes.NewBufferString("hunter2\n")

	out, errw, code := ta.run("key", "add", "web", "password", "--namespace", "frontend", "--rotation", "external", "--from-file", "-")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	if !strings.Contains(out, "web/password stored as GSM version 1") || !strings.Contains(errw, "commit the changed files") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out, errw)
	}
	value, err := ta.Store.AccessVersion(t.Context(), "projects/waxseal-test-project/secrets/web-password", "1")
	if err != nil || string(value) != "hunter2" {
		t.Errorf("stored %q, %v (trailing newline must be stripped)", value, err)
	}
	m, err := ta.Repo().Metadata("web")
	if err != nil || m.SealedSecret.Namespace != "frontend" || m.SealedSecret.Scope != "strict" {
		t.Errorf("metadata: %+v %v", m, err)
	}

	// A second key on the now-existing secret; generated.
	_, errw, code = ta.run("key", "add", "web", "token", "--generate", "--generator", "randomHex", "--bytes", "8")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	m, _ = ta.Repo().Metadata("web")
	if k := m.Key("token"); k == nil || k.Rotation.Mode != "generated" || k.Rotation.Generator.Bytes != 8 {
		t.Errorf("token = %+v", k)
	}

	// Creating a secret non-interactively without --namespace is a usage error.
	_, errw, code = ta.run("key", "add", "other", "k", "--from-file", "-")
	if code != ExitUsage || !strings.Contains(errw, "--namespace") {
		t.Errorf("exit %d\n%s", code, errw)
	}
}

func TestKeyAdd_InteractiveWalksEveryInput(t *testing.T) {
	ta := newTestApp(t, true)
	// secret, key, namespace, confirm create, scope, rotation, value
	ta.Prompter.Answers = []string{"web", "password", "frontend", "y", "strict", "external", "s3cret"}
	out, errw, code := ta.run("key", "add")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errw)
	}
	var flags []string
	for _, a := range ta.Prompter.Asked {
		flags = append(flags, a.Flag)
	}
	if strings.Join(flags, " ") != "<secret> <key> --namespace confirm --scope --rotation --from-file or --generate" {
		t.Errorf("asked: %v", flags)
	}
	value, _ := ta.Store.AccessVersion(t.Context(), "projects/waxseal-test-project/secrets/web-password", "1")
	if string(value) != "s3cret" {
		t.Errorf("stored %q", value)
	}
}

func TestKeySet(t *testing.T) {
	ta := newTestApp(t, false)
	ta.seedStore(t)

	file := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(file, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// api_key has an expiry, so a new one is required.
	_, errw, code := ta.run("key", "set", "my-app-secrets", "api_key", "--from-file", file)
	if code != ExitUsage || !strings.Contains(errw, "--expires") {
		t.Errorf("expiring key without --expires: exit %d\n%s", code, errw)
	}
	out, errw, code := ta.run("key", "set", "my-app-secrets", "api_key", "--from-file", file, "--expires", "2027-06-01")
	if code != 0 || !strings.Contains(out, "api_key set to GSM version 2") {
		t.Fatalf("exit %d\n%s%s", code, out, errw)
	}
	m, _ := ta.Repo().Metadata("my-app-secrets")
	if k := m.Key("api_key"); k.GSM.Version != "2" || k.Expiry.ExpiresAt != "2027-06-01T00:00:00Z" {
		t.Errorf("api_key = %+v", k)
	}

	// --generate on a generated key uses its stored generator.
	_, errw, code = ta.run("key", "set", "my-app-secrets", "database_password", "--generate")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	m, _ = ta.Repo().Metadata("my-app-secrets")
	if m.Key("database_password").GSM.Version != "4" {
		t.Errorf("version = %s", m.Key("database_password").GSM.Version)
	}

	// --generate on a key without a generator is a usage error, not a prompt.
	_, errw, code = ta.run("key", "set", "my-app-secrets", "database_username", "--generate")
	if code != ExitUsage || !strings.Contains(errw, "--generator") {
		t.Errorf("exit %d\n%s", code, errw)
	}

	// Bug 5: --yes never stands in for a value.
	_, errw, code = ta.run("key", "set", "my-app-secrets", "database_username", "--yes", "--no-input")
	if code != ExitUsage || !strings.Contains(errw, "--from-file or --generate") {
		t.Errorf("--yes without a value: exit %d\n%s", code, errw)
	}
}

func TestKeyEdit(t *testing.T) {
	ta := newTestApp(t, false)
	ta.seedStore(t)

	// Switching to generated without naming a generator uses the default one.
	_, errw, code := ta.run("key", "edit", "my-app-secrets", "api_key", "--rotation", "generated")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	if m, _ := ta.Repo().Metadata("my-app-secrets"); m.Key("api_key").Rotation.Generator.Kind != "randomBase64" {
		t.Errorf("default generator not applied: %+v", m.Key("api_key").Rotation)
	}
	_, errw, code = ta.run("key", "edit", "my-app-secrets", "api_key", "--rotation", "generated", "--generator", "randomHex", "--expires", "none")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	m, _ := ta.Repo().Metadata("my-app-secrets")
	if k := m.Key("api_key"); k.Rotation.Mode != "generated" || k.Rotation.Generator.Kind != "randomHex" || k.Expiry != nil {
		t.Errorf("api_key = %+v", k)
	}
	_, errw, code = ta.run("key", "edit", "my-app-secrets", "api_key", "--rotation", "manual")
	if code != ExitUsage || !strings.Contains(errw, "generated, external, static, unknown") {
		t.Errorf("invalid enum: exit %d\n%s", code, errw)
	}
}

func TestRotateAndReseal(t *testing.T) {
	ta := newTestApp(t, false)
	ta.seedStore(t)

	_, errw, code := ta.run("rotate", "my-app-secrets", "--no-input")
	if code != ExitUsage || !strings.Contains(errw, "confirmation required") {
		t.Errorf("rotate without --yes: exit %d\n%s", code, errw)
	}
	out, errw, code := ta.run("rotate", "my-app-secrets", "--yes")
	if code != 0 || !strings.Contains(out, "rotated 1 key(s)") || !strings.Contains(errw, "skipped api_key") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
	_, errw, code = ta.run("rotate", "my-app-secrets", "api_key", "--yes")
	if code != ExitFailure || !strings.Contains(errw, "key set") {
		t.Errorf("external key: exit %d\n%s", code, errw)
	}

	out, errw, code = ta.run("reseal")
	if code != 0 || strings.Count(out, "resealed") != 3 {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
	ta.Store.Clear()
	out, errw, code = ta.run("reseal", "-o", "json")
	if code != ExitFailure {
		t.Errorf("exit %d, want 1 when secrets fail\n%s", code, errw)
	}
	var r resealResult
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Failed != 3 {
		t.Errorf("json: %v\n%s", err, out)
	}
}

func TestSecretRetire(t *testing.T) {
	ta := newTestApp(t, false)
	_, errw, code := ta.run("secret", "retire", "tls-cert", "--reason", "replaced", "--delete-manifest", "--no-input")
	if code != ExitUsage || !strings.Contains(errw, "confirmation required to delete the manifest") {
		t.Errorf("exit %d\n%s", code, errw)
	}
	out, _, code := ta.run("secret", "retire", "tls-cert", "--reason", "replaced", "--delete-manifest", "-y")
	if code != 0 || !strings.Contains(out, "tls-cert retired") {
		t.Errorf("exit %d\n%s", code, out)
	}
	m, _ := ta.Repo().Metadata("tls-cert")
	if !m.IsRetired() {
		t.Error("not retired")
	}
}

func TestInitAndCertFetch(t *testing.T) {
	ta := newTestApp(t, false)
	ta.Flags.Repo = t.TempDir()

	_, errw, code := ta.run("init", "--no-input")
	if code != ExitUsage || !strings.Contains(errw, "--project") {
		t.Errorf("exit %d\n%s", code, errw)
	}
	out, errw, code := ta.run("init", "--project", "p", "--controller-namespace", "sealed")
	if code != 0 || !strings.Contains(out, "initialised for project p") || !strings.Contains(errw, "waxseal cert fetch") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
	_, errw, code = ta.run("init", "--project", "p")
	if code != ExitFailure || !strings.Contains(errw, "--force") {
		t.Errorf("second init: exit %d\n%s", code, errw)
	}

	_, errw, code = ta.run("cert", "fetch")
	if code != 0 || !strings.Contains(errw, "certificate stored") {
		t.Errorf("exit %d\n%s", code, errw)
	}
	_, errw, code = ta.run("cert", "fetch")
	if code != 0 || !strings.Contains(errw, "up to date") {
		t.Errorf("second fetch: exit %d\n%s", code, errw)
	}
	_, errw, code = ta.run("secret", "list")
	if code != 0 || !strings.Contains(errw, "No secrets are registered") {
		t.Errorf("exit %d\n%s", code, errw)
	}
}

func TestImportCommand(t *testing.T) {
	ta := newTestApp(t, false)
	if err := os.Remove(ta.Repo().MetadataPath("tls-cert")); err != nil {
		t.Fatal(err)
	}
	ta.Cluster.secrets["ingress-nginx/wildcard-tls"] = map[string][]byte{"tls.crt": []byte("C"), "tls.key": []byte("K")}

	_, errw, code := ta.run("import", "--no-input")
	if code != ExitUsage || !strings.Contains(errw, "confirmation required to import ingress-nginx-wildcard-tls") {
		t.Errorf("exit %d\n%s", code, errw)
	}
	out, errw, code := ta.run("import", "-y")
	if code != 0 || !strings.Contains(out, "imported ingress-nginx-wildcard-tls: 2 added") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
	if _, err := ta.Repo().Metadata("ingress-nginx-wildcard-tls"); err != nil {
		t.Error(err)
	}
}

func TestGCPProvisionDryRun(t *testing.T) {
	ta := newTestApp(t, false)
	out, errw, code := ta.run("gcp", "provision", "--project", "p", "--github-repo", "me/repo", "--dry-run")
	if code != 0 || !strings.Contains(out, "gcloud services enable --project=p secretmanager.googleapis.com") || !strings.Contains(out, "would run 6 gcloud steps") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
}

func TestRemindersCommands(t *testing.T) {
	ta := newTestApp(t, false)
	out, errw, code := ta.run("reminders", "configure", "--provider", "both", "--lead-days", "14, 3", "--calendar", "team@example.com")
	if code != 0 || !strings.Contains(out, "provider set to both") {
		t.Fatalf("exit %d\n%s%s", code, out, errw)
	}
	cfg, _ := ta.Repo().Config()
	if cfg.Reminders.Provider != "both" || cfg.Reminders.CalendarID != "team@example.com" || len(cfg.Reminders.LeadTimeDays) != 2 {
		t.Errorf("config = %+v", cfg.Reminders)
	}
	_, errw, code = ta.run("reminders", "configure", "--lead-days", "x")
	if code != ExitUsage {
		t.Errorf("bad lead days: exit %d\n%s", code, errw)
	}

	out, _, code = ta.run("reminders", "sync")
	if code != 0 || !strings.Contains(out, "2 created") || len(ta.Reminders.SyncCalls) != 1 {
		t.Errorf("exit %d\n%s", code, out)
	}
	_, _, code = ta.run("reminders", "clear", "tls-cert")
	if code != 0 || len(ta.Reminders.DeleteCalls) != 1 {
		t.Errorf("exit %d", code)
	}

	_, errw, code = ta.run("reminders", "configure", "--provider", "none")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	ta.NewReminders = func(context.Context, *config.RemindersConfig) (reminder.Provider, error) {
		return nil, reminder.ErrDisabled
	}
	_, errw, code = ta.run("reminders", "sync")
	if code != ExitFailure || !strings.Contains(errw, "reminders configure") {
		t.Errorf("disabled: exit %d\n%s", code, errw)
	}
}

// Every mutating command's --dry-run -o json output is pinned: it is the
// schema scripts rely on, and a dry run must never change anything.
func TestDryRunJSONGolden(t *testing.T) {
	cases := [][]string{
		{"key", "add", "web", "password", "--namespace", "frontend", "--rotation", "external", "--from-file", "-"},
		{"key", "set", "my-app-secrets", "database_password", "--generate"},
		{"rotate", "my-app-secrets"},
		{"reseal", "my-app-secrets", "--skip-cert-check"},
		{"secret", "retire", "tls-cert", "--delete-manifest"},
		{"import", "ingress-nginx-wildcard-tls"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args[:2], "_"), func(t *testing.T) {
			ta := newTestApp(t, false)
			ta.seedStore(t)
			ta.Stdin = bytes.NewBufferString("v\n")
			if args[0] == "import" {
				os.Remove(ta.Repo().MetadataPath("tls-cert"))
				ta.Cluster.secrets["ingress-nginx/wildcard-tls"] = map[string][]byte{"tls.crt": []byte("C")}
			}
			before := snapshot(t, ta.Repo().Root())
			out, errw, code := ta.run(append(args, "--dry-run", "-o", "json")...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, errw)
			}
			if after := snapshot(t, ta.Repo().Root()); after != before {
				t.Error("dry run changed files in the repo")
			}
			// Paths are per-test temp dirs; normalise them.
			normalised := strings.ReplaceAll(out, ta.Repo().Root(), "<repo>")
			testutil.AssertGolden(t, filepath.Join("testdata", "json", strings.Join(args[:2], "_")+".golden"), []byte(normalised))
		})
	}
}

func snapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, _ := os.ReadFile(path)
		b.WriteString(path + "\n" + string(data) + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
