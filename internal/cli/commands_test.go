package cli

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/ops"
)

func TestSecretList(t *testing.T) {
	ta := newTestApp(t, false)
	out, errw, code := ta.run("secret", "list")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errw)
	}
	if !strings.HasPrefix(out, "SECRET") || !regexp.MustCompile(`my-app-secrets +my-app/my-app-secrets +active +4 +external,generated,static,unknown +-`).MatchString(out) {
		t.Errorf("table:\n%s", out)
	}
	if errw != "" {
		t.Errorf("stderr should be empty on success, got:\n%s", errw)
	}

	out, _, _ = ta.run("secret", "list", "-o", "json")
	var r listResult
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Secrets) != 3 {
		t.Errorf("json: %v\n%s", err, out)
	}
}

func TestSecretShow(t *testing.T) {
	ta := newTestApp(t, false)
	out, _, code := ta.run("secret", "show", "my-app-secrets")
	if code != 0 || !strings.Contains(out, "Scope:") || !strings.Contains(out, "database_password") {
		t.Errorf("exit %d\n%s", code, out)
	}

	_, errw, code := ta.run("secret", "show", "nope")
	if code != ExitFailure || !strings.Contains(errw, "Error:") || !strings.Contains(errw, "hint:") {
		t.Errorf("unknown secret: exit %d\n%s", code, errw)
	}

	// On a terminal the missing argument is picked from the active secrets.
	tty := newTestApp(t, true)
	tty.Prompter.Answers = []string{"tls-cert"}
	out, errw, code = tty.run("secret", "show")
	if code != 0 || !strings.Contains(out, "wildcard-tls") {
		t.Errorf("picker: exit %d\n%s%s", code, out, errw)
	}
	if len(tty.Prompter.Asked) != 1 || tty.Prompter.Asked[0].Flag != "<secret>" {
		t.Errorf("asked %v", tty.Prompter.Asked)
	}
}

func TestCheck(t *testing.T) {
	ta := newTestApp(t, false)
	ta.seedStore(t)

	out, errw, code := ta.run("check")
	if code != 0 {
		t.Fatalf("healthy fixture: exit %d\n%s", code, errw)
	}
	if out != "" {
		t.Errorf("text findings go to stderr, stdout had:\n%s", out)
	}
	for _, name := range ops.Checks.Values() {
		if !strings.Contains(errw, "✓ "+name) {
			t.Errorf("no positive line for %s:\n%s", name, errw)
		}
	}

	// Break GSM: exit 1, findings still shown, JSON still valid.
	ta.Store.Clear()
	out, errw, code = ta.run("check", "gsm", "-o", "json")
	if code != ExitFailure {
		t.Errorf("exit %d, want 1\n%s", code, errw)
	}
	var r checkResult
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Severity != ops.SeverityError {
		t.Errorf("json: %v\n%s", err, out)
	}
	if strings.Contains(errw, "Error:") {
		t.Errorf("a failed check must not also print Error:\n%s", errw)
	}

	// Warnings: exit 0, or 2 with --fail-on-warning.
	ta.seedStore(t)
	_, _, code = ta.run("check", "expiry", "--warn-days", "60")
	if code != 0 {
		t.Errorf("warnings alone: exit %d", code)
	}
	_, _, code = ta.run("check", "expiry", "--warn-days", "60", "--fail-on-warning")
	if code != ExitUsage {
		t.Errorf("--fail-on-warning: exit %d, want 2", code)
	}

	// An unknown check name is a usage error.
	_, errw, code = ta.run("check", "vibes")
	if code != ExitUsage {
		t.Errorf("exit %d\n%s", code, errw)
	}

	// A named check whose credentials are absent fails; unnamed it is skipped.
	ta.CheckADC = func(context.Context) error { return errBoom }
	_, errw, code = ta.run("check", "gsm")
	if code != ExitFailure || !strings.Contains(errw, "gcloud auth application-default login") {
		t.Errorf("named gsm without creds: exit %d\n%s", code, errw)
	}
	_, errw, code = ta.run("check")
	if code != 0 || !strings.Contains(errw, "skipped") {
		t.Errorf("all-checks without creds: exit %d\n%s", code, errw)
	}
}

func TestDiscover(t *testing.T) {
	ta := newTestApp(t, false)
	out, errw, code := ta.run("discover")
	if code != 0 || !strings.Contains(out, "apps/my-app/sealed-secret.yaml") || !strings.Contains(out, "my-app-secrets") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
	if strings.Contains(errw, "Next:") {
		t.Error("nothing to import, so no next step")
	}

	if err := os.Remove(ta.Repo().MetadataPath("tls-cert")); err != nil {
		t.Fatal(err)
	}
	out, errw, code = ta.run("discover")
	if code != 0 || !strings.Contains(out, "(new)") || !strings.Contains(errw, "waxseal import ingress-nginx-wildcard-tls") {
		t.Errorf("exit %d\n%s%s", code, out, errw)
	}
}

func TestExitCodes(t *testing.T) {
	ta := newTestApp(t, false)
	cases := []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"secret", "list", "--bogus"}, ExitUsage, "unknown flag"},
		{[]string{"secret", "list", "extra"}, ExitUsage, "unknown command"},
		{[]string{"secret", "show", "a", "b"}, ExitUsage, "accepts at most 1 arg"},
		{[]string{"secret", "list", "-o", "xml"}, ExitUsage, "invalid output format"},
		{[]string{"no-such-command"}, ExitUsage, "unknown command"},
	}
	for _, tc := range cases {
		_, errw, code := ta.run(tc.args...)
		if code != tc.code || !strings.Contains(errw, tc.msg) {
			t.Errorf("%v: exit %d (want %d), stderr:\n%s", tc.args, code, tc.code, errw)
		}
	}

	// Not initialised: exit 1 with a hint to init.
	ta.Flags.Repo = t.TempDir()
	_, errw, code := ta.run("secret", "list")
	if code != ExitFailure || !strings.Contains(errw, "waxseal init") {
		t.Errorf("uninitialised repo: exit %d\n%s", code, errw)
	}
}
