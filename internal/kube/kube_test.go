package kube

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/proc"
)

// script maps a joined argv to its stdout or error.
type script map[string]struct {
	out string
	err error
}

func (s script) runner(t *testing.T) proc.Runner {
	return func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		r, ok := s[key]
		if !ok {
			t.Fatalf("unexpected command: %s", key)
		}
		return []byte(r.out), r.err
	}
}

func TestGetSecret(t *testing.T) {
	c := Client{run: script{
		"kubectl get secret app -n prod -o json": {out: `{"data":{"password":"aHVudGVyMg==","empty":""}}`},
		"kubectl get secret nope -n prod -o json": {err: &proc.ExitError{Name: "kubectl", Code: 1,
			Stderr: `Error from server (NotFound): secrets "nope" not found`}},
		"kubectl get secret app -n prod -o json ": {},
	}.runner(t)}

	got, err := c.GetSecret(context.Background(), "prod", "app")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{"password": []byte("hunter2"), "empty": {}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	if _, err := c.GetSecret(context.Background(), "prod", "nope"); !core.IsNotFound(err) {
		t.Errorf("missing secret: got %v, want not found", err)
	}
}

func TestFindController(t *testing.T) {
	pods := "kubectl get pods -A -l app.kubernetes.io/name=sealed-secrets -o jsonpath={.items[0].metadata.namespace}"
	c := Client{run: script{
		pods: {out: "sealed-secrets"},
		"kubectl get svc -n sealed-secrets sealed-secrets-controller": {err: &proc.ExitError{Name: "kubectl", Code: 1}},
		"kubectl get svc -n sealed-secrets sealed-secrets":            {out: "ok"},
	}.runner(t)}
	ns, svc, err := c.FindController(context.Background())
	if err != nil || ns != "sealed-secrets" || svc != "sealed-secrets" {
		t.Errorf("got %q %q %v", ns, svc, err)
	}

	none := Client{run: script{pods: {out: ""}}.runner(t)}
	if _, _, err := none.FindController(context.Background()); !core.IsNotFound(err) {
		t.Errorf("no controller: got %v", err)
	}
}

func TestListNamespaces(t *testing.T) {
	c := Client{run: script{
		"kubectl get namespaces -o jsonpath={.items[*].metadata.name}": {out: "default kube-system prod"},
	}.runner(t)}
	got, err := c.ListNamespaces(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"default", "kube-system", "prod"}) {
		t.Errorf("got %v, %v", got, err)
	}
}
