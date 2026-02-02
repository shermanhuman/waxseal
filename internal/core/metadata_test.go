package core

import (
	"errors"
	"testing"
)

func TestParseMetadata_Valid(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-secret-password
      version: "3"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32
`
	m, err := ParseMetadata([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseMetadata failed: %v", err)
	}

	if m.ShortName != "my-secret" {
		t.Errorf("shortName = %q, want %q", m.ShortName, "my-secret")
	}
	if len(m.Keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(m.Keys))
	}
	if m.Keys[0].KeyName != "password" {
		t.Errorf("keys[0].keyName = %q, want %q", m.Keys[0].KeyName, "password")
	}
}

func TestParseMetadata_RejectsGSMAlias(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-secret-password
      version: latest
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for GSM alias 'latest'")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestParseMetadata_RejectsUnknownFields(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
unknownField: value
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-secret-password
      version: "1"
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseMetadata_MissingShortName(t *testing.T) {
	yaml := `
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-secret-password
      version: "1"
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing shortName")
	}
}

func TestParseMetadata_InvalidScope(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: invalid-scope
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-secret-password
      version: "1"
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
}

func TestParseMetadata_InvalidSourceKind(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: password
    source:
      kind: invalid
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid source.kind")
	}
}

func TestParseMetadata_ComputedKey(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: username
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/username
      version: "1"
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/password
      version: "2"
  - keyName: DATABASE_URL
    source:
      kind: computed
    computed:
      kind: template
      template: "postgresql://{{username}}:{{password}}@localhost:5432/mydb"
      inputs:
        - var: username
          ref:
            keyName: username
        - var: password
          ref:
            keyName: password
`
	m, err := ParseMetadata([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseMetadata failed: %v", err)
	}

	if len(m.Keys) != 3 {
		t.Fatalf("len(keys) = %d, want 3", len(m.Keys))
	}

	dbUrlKey := m.Keys[2]
	if dbUrlKey.Source.Kind != "computed" {
		t.Errorf("keys[2].source.kind = %q, want %q", dbUrlKey.Source.Kind, "computed")
	}
	if dbUrlKey.Computed.Template == "" {
		t.Error("keys[2].computed.template should not be empty")
	}
}

func TestParseMetadata_Expiry(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: api_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/api-key
      version: "5"
    expiry:
      expiresAt: "2025-12-31T23:59:59Z"
      source: vendor
`
	m, err := ParseMetadata([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseMetadata failed: %v", err)
	}

	if m.Keys[0].Expiry == nil {
		t.Fatal("keys[0].expiry should not be nil")
	}
	if m.Keys[0].Expiry.ExpiresAt != "2025-12-31T23:59:59Z" {
		t.Errorf("expiry.expiresAt = %q, want %q", m.Keys[0].Expiry.ExpiresAt, "2025-12-31T23:59:59Z")
	}
}

func TestParseMetadata_InvalidExpiryFormat(t *testing.T) {
	yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: api_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/api-key
      version: "5"
    expiry:
      expiresAt: "not-a-date"
`
	_, err := ParseMetadata([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid expiry format")
	}
}

func TestParseMetadata_RotationModes(t *testing.T) {
	modes := []string{"generated", "external", "manual", "unknown"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			yaml := `
shortName: my-secret
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-secret
  namespace: default
  scope: strict
keys:
  - keyName: password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/password
      version: "1"
    rotation:
      mode: ` + mode
			if mode == "generated" {
				yaml += `
      generator:
        kind: randomBase64
        bytes: 32`
			}

			_, err := ParseMetadata([]byte(yaml))
			if err != nil {
				t.Fatalf("ParseMetadata failed for mode %q: %v", mode, err)
			}
		})
	}
}

func TestSecretMetadata_IsRetired(t *testing.T) {
	m := &SecretMetadata{Status: "retired"}
	if !m.IsRetired() {
		t.Error("IsRetired() should return true for retired status")
	}

	m.Status = "active"
	if m.IsRetired() {
		t.Error("IsRetired() should return false for active status")
	}
}

func TestGSMRef_NumericVersionOnly(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{"1", false},
		{"123", false},
		{"999999", false},
		{"latest", true},
		{"1.0", true},
		{"v1", true},
		{"", true},
		{"1a", true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			g := &GSMRef{
				SecretResource: "projects/p/secrets/s",
				Version:        tt.version,
			}
			err := g.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() for version %q: got err=%v, wantErr=%v", tt.version, err, tt.wantErr)
			}
		})
	}
}
