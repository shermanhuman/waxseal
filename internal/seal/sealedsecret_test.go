package seal

import (
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestParseSealedSecret_Valid(t *testing.T) {
	yaml := `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
  namespace: default
spec:
  encryptedData:
    password: AgBY3...encrypted...
    username: AgCX4...encrypted...
`
	ss, err := ParseSealedSecret([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseSealedSecret failed: %v", err)
	}

	if ss.Metadata.Name != "my-secret" {
		t.Errorf("name = %q, want %q", ss.Metadata.Name, "my-secret")
	}
	if ss.Metadata.Namespace != "default" {
		t.Errorf("namespace = %q, want %q", ss.Metadata.Namespace, "default")
	}
	if len(ss.Spec.EncryptedData) != 2 {
		t.Errorf("len(encryptedData) = %d, want 2", len(ss.Spec.EncryptedData))
	}
}

func TestParseSealedSecret_WrongKind(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
`
	_, err := ParseSealedSecret([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for wrong kind")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestParseSealedSecret_MissingName(t *testing.T) {
	yaml := `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  namespace: default
spec:
  encryptedData:
    password: AgBY3...
`
	_, err := ParseSealedSecret([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParseSealedSecret_MissingNamespace(t *testing.T) {
	yaml := `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
spec:
  encryptedData:
    password: AgBY3...
`
	_, err := ParseSealedSecret([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing namespace")
	}
}

func TestSealedSecret_GetScope(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantScope   string
	}{
		{
			name:        "no annotations",
			annotations: nil,
			wantScope:   ScopeStrict,
		},
		{
			name:        "no scope annotation",
			annotations: map[string]string{"other": "value"},
			wantScope:   ScopeStrict,
		},
		{
			name:        "strict scope",
			annotations: map[string]string{AnnotationScope: "strict"},
			wantScope:   ScopeStrict,
		},
		{
			name:        "namespace-wide scope",
			annotations: map[string]string{AnnotationScope: "namespace-wide"},
			wantScope:   ScopeNamespaceWide,
		},
		{
			name:        "cluster-wide scope",
			annotations: map[string]string{AnnotationScope: "cluster-wide"},
			wantScope:   ScopeClusterWide,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := &SealedSecret{
				Metadata: ObjectMeta{
					Annotations: tt.annotations,
				},
			}
			if got := ss.GetScope(); got != tt.wantScope {
				t.Errorf("GetScope() = %q, want %q", got, tt.wantScope)
			}
		})
	}
}

func TestSealedSecret_GetEncryptedKeys(t *testing.T) {
	ss := &SealedSecret{
		Spec: SealedSecretSpec{
			EncryptedData: map[string]string{
				"username": "encrypted1",
				"password": "encrypted2",
				"api_key":  "encrypted3",
			},
		},
	}

	keys := ss.GetEncryptedKeys()
	if len(keys) != 3 {
		t.Errorf("len(keys) = %d, want 3", len(keys))
	}

	// Check all keys are present (order doesn't matter)
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}
	for _, expected := range []string{"username", "password", "api_key"} {
		if !keyMap[expected] {
			t.Errorf("missing key %q", expected)
		}
	}
}

func TestSealedSecret_GetSecretType(t *testing.T) {
	tests := []struct {
		name     string
		template *SecretTemplateSpec
		want     string
	}{
		{
			name:     "no template",
			template: nil,
			want:     "Opaque",
		},
		{
			name:     "empty type",
			template: &SecretTemplateSpec{},
			want:     "Opaque",
		},
		{
			name:     "docker config",
			template: &SecretTemplateSpec{Type: "kubernetes.io/dockerconfigjson"},
			want:     "kubernetes.io/dockerconfigjson",
		},
		{
			name:     "tls",
			template: &SecretTemplateSpec{Type: "kubernetes.io/tls"},
			want:     "kubernetes.io/tls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := &SealedSecret{
				Spec: SealedSecretSpec{
					Template: tt.template,
				},
			}
			if got := ss.GetSecretType(); got != tt.want {
				t.Errorf("GetSecretType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSealedSecret_WithTemplate(t *testing.T) {
	yaml := `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: docker-creds
  namespace: default
  annotations:
    sealedsecrets.bitnami.com/scope: namespace-wide
spec:
  encryptedData:
    .dockerconfigjson: AgBY3...encrypted...
  template:
    type: kubernetes.io/dockerconfigjson
`
	ss, err := ParseSealedSecret([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseSealedSecret failed: %v", err)
	}

	if ss.GetScope() != ScopeNamespaceWide {
		t.Errorf("scope = %q, want %q", ss.GetScope(), ScopeNamespaceWide)
	}
	if ss.GetSecretType() != "kubernetes.io/dockerconfigjson" {
		t.Errorf("type = %q, want %q", ss.GetSecretType(), "kubernetes.io/dockerconfigjson")
	}
}
