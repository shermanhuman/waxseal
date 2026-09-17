package files

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Whatever is written must parse back to the same value. This is the format
// contract the marshal-based writer in the rewrite has to keep.
func TestSerializeMetadata_RoundTrip(t *testing.T) {
	gsm := func(id, v string) *core.GSMRef {
		return &core.GSMRef{SecretResource: "projects/p/secrets/" + id, Version: v}
	}
	tests := []struct {
		name string
		meta core.SecretMetadata
	}{
		{
			name: "every optional field",
			meta: core.SecretMetadata{
				ShortName:    "app",
				ManifestPath: "apps/app/sealed.yaml",
				SealedSecret: core.SealedSecretRef{Name: "app", Namespace: "prod", Scope: "namespace-wide", Type: "kubernetes.io/tls"},
				Status:       "active",
				Keys: []core.KeyMetadata{
					{
						KeyName:       "password",
						Source:        core.SourceConfig{Kind: "gsm"},
						GSM:           gsm("app-password", "3"),
						Rotation:      &core.RotationConfig{Mode: "generated", Generator: &core.GeneratorConfig{Kind: "randomHex", Bytes: 24}},
						Expiry:        &core.ExpiryConfig{ExpiresAt: "2027-01-02T03:04:05Z"},
						OperatorHints: &core.OperatorHints{GSM: gsm("app-password-hints", "1"), Format: "json"},
					},
					{
						KeyName: "url",
						Source:  core.SourceConfig{Kind: "computed"},
						Computed: &core.ComputedConfig{
							Kind:     "template",
							Template: `postgres://{{user}}:{{pw}}@{{host}}/db?opt="x"`,
							Inputs: []core.InputRef{
								{Var: "pw", Ref: core.KeyRef{KeyName: "password"}},
								{Var: "user", Ref: core.KeyRef{ShortName: "shared", KeyName: "username"}},
							},
							Params: map[string]string{"host": "db.internal:5432", "note": "a: b #c"},
						},
					},
					{
						KeyName:  "payload",
						Source:   core.SourceConfig{Kind: "computed"},
						Rotation: &core.RotationConfig{Mode: "static"},
						Computed: &core.ComputedConfig{Kind: "template", Template: "{{secret}}", GSM: gsm("app-payload", "12")},
					},
				},
			},
		},
		{
			name: "retired with free text that is not a plain YAML scalar",
			meta: core.SecretMetadata{
				ShortName:    "old",
				ManifestPath: "apps/old/sealed.yaml",
				SealedSecret: core.SealedSecretRef{Name: "old", Namespace: "default", Scope: "strict"},
				Status:       "retired",
				RetiredAt:    "2026-01-02T03:04:05Z",
				RetireReason: "moved: see #42",
				ReplacedBy:   "new",
				Keys: []core.KeyMetadata{
					{KeyName: "k", Source: core.SourceConfig{Kind: "gsm"}, GSM: gsm("old-k", "1")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := SerializeMetadata(&tt.meta)
			got, err := core.ParseMetadata([]byte(out))
			if err != nil {
				t.Fatalf("ParseMetadata: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(*got, tt.meta) {
				t.Errorf("round trip changed the value\n got: %+v\nwant: %+v\nyaml:\n%s", *got, tt.meta, out)
			}
		})
	}
}

// Writing a fixture back must not change it, so that touching one key does
// not rewrite a user's whole file.
func TestSerializeMetadata_FixturesAreStable(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/infra-repo/.waxseal/metadata/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			m, err := core.ParseMetadata(data)
			if err != nil {
				t.Fatalf("ParseMetadata: %v", err)
			}
			again, err := core.ParseMetadata([]byte(SerializeMetadata(m)))
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if !reflect.DeepEqual(m, again) {
				t.Errorf("fixture does not survive a write\n got: %+v\nwant: %+v", again, m)
			}
		})
	}
}
