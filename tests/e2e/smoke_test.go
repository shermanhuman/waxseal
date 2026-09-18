//go:build e2e

// Package e2e is the smoke suite: the new CLI, in-process, against a real
// kind cluster with a real sealed-secrets controller, real kubeseal and
// kubectl, and a fake Secret Manager. It covers exactly what the unit
// fakes cannot: that the controller decrypts what waxseal seals.
//
// Run: kind create cluster --config tests/e2e/kind-config.yaml && helm ...
// (see .github/workflows/e2e.yml), then go test -tags e2e ./tests/e2e/
//
// With WAXSEAL_GSM_E2E=<project>, the real Secret Manager of that project
// is used instead of the fake; secrets it creates are deleted afterwards.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/cli"
	"github.com/shermanhuman/waxseal/internal/store"
)

const namespace = "waxseal-smoke"

type harness struct {
	t     *testing.T
	repo  string
	app   *cli.App
	out   bytes.Buffer
	errw  bytes.Buffer
	fake  *store.FakeStore
	gsm   *store.GSMStore
	made  []string // GSM resources to delete afterwards
	stdin *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, repo: t.TempDir(), stdin: &bytes.Buffer{}}
	h.app = cli.NewApp()
	h.app.Stdin = h.stdin
	h.app.Stdout, h.app.Stderr = &h.out, &h.errw
	h.app.IsTTY = func(any) bool { return false }
	h.app.Flags.Repo = h.repo

	if project := os.Getenv("WAXSEAL_GSM_E2E"); project != "" {
		gsm, err := store.NewGSMStore(context.Background(), project)
		if err != nil {
			t.Fatalf("open GSM for %s: %v", project, err)
		}
		h.gsm = gsm
		t.Cleanup(func() {
			for _, r := range h.made {
				_ = gsm.DeleteSecret(context.Background(), r)
			}
			_ = gsm.Close()
		})
	} else {
		h.fake = store.NewFakeStore()
		h.app.NewStore = func(context.Context, string) (store.Store, func(), error) { return h.fake, func() {}, nil }
		h.app.CheckADC = func(context.Context) error { return nil }
	}
	return h
}

func (h *harness) run(args ...string) (string, int) {
	h.t.Helper()
	h.out.Reset()
	h.errw.Reset()
	h.app.Flags = cli.GlobalFlags{Repo: h.repo}
	code := cli.Main(context.Background(), h.app, append(args, "--no-input", "--yes"))
	h.t.Logf("$ waxseal %s\n%s%s", strings.Join(args, " "), h.out.String(), h.errw.String())
	return h.out.String() + h.errw.String(), code
}

func (h *harness) must(args ...string) string {
	h.t.Helper()
	out, code := h.run(args...)
	if code != 0 {
		h.t.Fatalf("waxseal %s: exit %d", strings.Join(args, " "), code)
	}
	return out
}

func (h *harness) kubectl(args ...string) string {
	h.t.Helper()
	cmd := exec.Command("kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// clusterSecret waits for the controller to produce the Secret and returns
// its decoded data.
func (h *harness) clusterSecret(name string) map[string]string {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		cmd := exec.Command("kubectl", "get", "secret", name, "-n", namespace, "-o", "json")
		out, err := cmd.Output()
		if err == nil {
			var s struct {
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(out, &s) == nil {
				decoded := map[string]string{}
				for k, v := range s.Data {
					b, _ := base64.StdEncoding.DecodeString(v)
					decoded[k] = string(b)
				}
				return decoded
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("secret %s/%s never appeared", namespace, name)
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *harness) project() string {
	if p := os.Getenv("WAXSEAL_GSM_E2E"); p != "" {
		return p
	}
	return "fake-project"
}

func TestSmoke(t *testing.T) {
	h := newHarness(t)
	ns, svc, err := findController()
	if err != nil {
		t.Fatalf("no sealed-secrets controller: %v", err)
	}
	h.kubectl("create", "namespace", namespace, "--dry-run=client", "-o", "yaml")
	_ = exec.Command("kubectl", "create", "namespace", namespace).Run()
	t.Cleanup(func() { _ = exec.Command("kubectl", "delete", "namespace", namespace, "--wait=false").Run() })

	// init + cert fetch: the cert comes from the real controller.
	h.must("init", "--project", h.project(), "--controller-namespace", ns, "--controller-name", svc)
	h.must("cert", "fetch")
	if _, err := os.Stat(filepath.Join(h.repo, "keys", "pub-cert.pem")); err != nil {
		t.Fatal(err)
	}

	// A secret with every scope, sealed by real kubeseal; the controller
	// must decrypt each.
	for _, scope := range []string{"strict", "namespace-wide", "cluster-wide"} {
		name := "smoke-" + scope
		h.stdin.WriteString("value-for-" + scope + "\n")
		h.must("key", "add", name, "password", "--namespace", namespace, "--scope", scope, "--rotation", "external", "--from-file", "-")
		h.made = append(h.made, fmt.Sprintf("projects/%s/secrets/%s-password", h.project(), name))
		h.kubectl("apply", "-f", filepath.Join(h.repo, "apps", name, "sealed-secret.yaml"))
		if got := h.clusterSecret(name)["password"]; got != "value-for-"+scope {
			t.Errorf("%s: controller decrypted %q", scope, got)
		}
	}

	// key set: the new value reaches the cluster.
	h.stdin.WriteString("rotated-by-hand\n")
	h.must("key", "set", "smoke-strict", "password", "--from-file", "-")
	h.kubectl("apply", "-f", filepath.Join(h.repo, "apps", "smoke-strict", "sealed-secret.yaml"))
	waitFor(t, func() bool { return h.clusterSecret("smoke-strict")["password"] == "rotated-by-hand" })

	// A generated key, rotated: a new value the controller can read.
	h.must("key", "add", "smoke-strict", "token", "--generate", "--generator", "randomHex", "--bytes", "8")
	h.made = append(h.made, fmt.Sprintf("projects/%s/secrets/smoke-strict-token", h.project()))
	h.must("rotate", "smoke-strict")
	h.kubectl("apply", "-f", filepath.Join(h.repo, "apps", "smoke-strict", "sealed-secret.yaml"))
	waitFor(t, func() bool { return len(h.clusterSecret("smoke-strict")["token"]) == 16 })

	// discover / import round trip: forget the metadata, import it back
	// from the cluster, and reseal; the result must still decrypt.
	if err := os.Remove(filepath.Join(h.repo, ".waxseal", "metadata", "smoke-namespace-wide.yaml")); err != nil {
		t.Fatal(err)
	}
	out := h.must("discover")
	if !strings.Contains(out, "(new)") {
		t.Fatalf("discover did not report the unregistered manifest:\n%s", out)
	}
	h.must("import", namespace+"-smoke-namespace-wide")
	h.made = append(h.made, fmt.Sprintf("projects/%s/secrets/%s-smoke-namespace-wide-password", h.project(), namespace))
	h.must("reseal", namespace+"-smoke-namespace-wide", "--skip-cert-check")
	h.kubectl("apply", "-f", filepath.Join(h.repo, "apps", "smoke-namespace-wide", "sealed-secret.yaml"))
	waitFor(t, func() bool { return h.clusterSecret("smoke-namespace-wide")["password"] == "value-for-namespace-wide" })

	// check: everything green, including the cluster comparison.
	if out, code := h.run("check"); code != 0 {
		t.Errorf("check: exit %d\n%s", code, out)
	}

	// Tamper with the cluster: check cluster must go red.
	h.kubectl("patch", "secret", "smoke-strict", "-n", namespace, "--type=json", "-p", `[{"op":"remove","path":"/data/token"}]`)
	if _, code := h.run("check", "cluster"); code != 1 {
		t.Errorf("check cluster after tampering: exit %d, want 1", code)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(2 * time.Second)
	}
}

func findController() (ns, svc string, err error) {
	out, err := exec.Command("kubectl", "get", "svc", "-A", "-l", "app.kubernetes.io/name=sealed-secrets",
		"-o", "jsonpath={.items[0].metadata.namespace} {.items[0].metadata.name}").Output()
	if err != nil {
		return "", "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected output %q", out)
	}
	return parts[0], parts[1], nil
}
