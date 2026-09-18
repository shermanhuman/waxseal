package seal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/proc"
)

func TestKubesealSealer_Argv(t *testing.T) {
	tests := []struct {
		scope    string
		wantArgs string
	}{
		{ScopeStrict, "--raw --cert keys/pub-cert.pem --scope strict --namespace prod --name app"},
		{ScopeNamespaceWide, "--raw --cert keys/pub-cert.pem --scope namespace-wide --namespace prod"},
		{ScopeClusterWide, "--raw --cert keys/pub-cert.pem --scope cluster-wide --namespace prod"},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			var gotArgs, gotStdin string
			s := &KubesealSealer{certPath: "keys/pub-cert.pem", run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
				gotArgs, gotStdin = strings.Join(args, " "), string(stdin)
				return []byte("AgB...\n"), nil
			}}
			got, err := s.Seal("app", "prod", "password", []byte("hunter2"), tt.scope)
			if err != nil || got != "AgB..." {
				t.Fatalf("got %q, %v", got, err)
			}
			if gotArgs != tt.wantArgs {
				t.Errorf("args = %q, want %q", gotArgs, tt.wantArgs)
			}
			if gotStdin != "hunter2" {
				t.Errorf("stdin = %q", gotStdin)
			}
		})
	}
}

func TestKubesealSealer_Error(t *testing.T) {
	s := &KubesealSealer{run: func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, &proc.ExitError{Name: "kubeseal", Code: 1, Stderr: "error: cannot read cert"}
	}}
	_, err := s.Seal("app", "prod", "k", []byte("v"), ScopeStrict)
	if err == nil || !strings.Contains(err.Error(), "cannot read cert") {
		t.Errorf("got %v, want the kubeseal stderr", err)
	}
}

func TestKubeseal_FetchCert(t *testing.T) {
	pemData := generateTestCertPEM(t)
	var gotArgs string
	k := Kubeseal{run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		gotArgs = strings.Join(args, " ")
		return pemData, nil
	}}
	got, err := k.FetchCert(context.Background(), "kube-system", "sealed-secrets")
	if err != nil || string(got) != string(pemData) {
		t.Fatalf("got %q, %v", got, err)
	}
	if gotArgs != "--fetch-cert --controller-namespace=kube-system --controller-name=sealed-secrets" {
		t.Errorf("args = %q", gotArgs)
	}

	garbage := Kubeseal{run: func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("Error: cannot connect\n"), nil
	}}
	if _, err := garbage.FetchCert(context.Background(), "a", "b"); err == nil {
		t.Error("non-certificate output must be an error")
	}

	missing := Kubeseal{run: func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, proc.ErrNotInstalled
	}}
	if _, err := missing.FetchCert(context.Background(), "a", "b"); !errors.Is(err, proc.ErrNotInstalled) {
		t.Errorf("got %v, want ErrNotInstalled", err)
	}
}
