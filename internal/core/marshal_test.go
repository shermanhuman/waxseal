package core

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func fixturePaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, pattern := range []string{
		"../../testdata/infra-repo/.waxseal/metadata/*.yaml",
		"../../testdata/golden/input_*.yaml",
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, m...)
	}
	if len(paths) == 0 {
		t.Fatal("no metadata fixtures found")
	}
	return paths
}

// Parse and Marshal share struct tags, so every field must survive a write.
func TestMarshal_RoundTrip(t *testing.T) {
	gsm := func(id, v string) *GSMRef {
		return &GSMRef{SecretResource: "projects/p/secrets/" + id, Version: v}
	}
	tests := []struct {
		name string
		meta SecretMetadata
	}{
		{
			name: "every optional field",
			meta: SecretMetadata{
				ShortName:    "app",
				ManifestPath: "apps/app/sealed.yaml",
				SealedSecret: SealedSecretRef{Name: "app", Namespace: "prod", Scope: "namespace-wide", Type: "kubernetes.io/tls"},
				Status:       "active",
				Keys: []KeyMetadata{
					{
						KeyName:       "password",
						Source:        SourceConfig{Kind: "gsm"},
						GSM:           gsm("app-password", "3"),
						Rotation:      &RotationConfig{Mode: "generated", Generator: &GeneratorConfig{Kind: "randomHex", Bytes: 24}},
						Expiry:        &ExpiryConfig{ExpiresAt: "2027-01-02T03:04:05Z"},
						OperatorHints: &OperatorHints{GSM: gsm("app-password-hints", "1"), Format: "json"},
					},
					{
						KeyName: "url",
						Source:  SourceConfig{Kind: "computed"},
						Computed: &ComputedConfig{
							Kind:     "template",
							Template: `postgres://{{user}}:{{pw}}@{{host}}/db?opt="x"`,
							Inputs: []InputRef{
								{Var: "pw", Ref: KeyRef{KeyName: "password"}},
								{Var: "user", Ref: KeyRef{ShortName: "shared", KeyName: "username"}},
							},
							Params: map[string]string{"host": "db.internal:5432", "note": "a: b #c", "port": "5432"},
						},
					},
					{
						KeyName:  "payload",
						Source:   SourceConfig{Kind: "computed"},
						Rotation: &RotationConfig{Mode: "static"},
						Computed: &ComputedConfig{Kind: "template", Template: "{{secret}}", GSM: gsm("app-payload", "12")},
					},
				},
			},
		},
		{
			name: "free text that is not a plain YAML scalar",
			meta: SecretMetadata{
				ShortName:    "old",
				ManifestPath: "apps/old/sealed.yaml",
				SealedSecret: SealedSecretRef{Name: "old", Namespace: "default", Scope: "strict"},
				Status:       "retired",
				RetiredAt:    "2026-01-02T03:04:05Z",
				RetireReason: "moved: see #42\nsecond line",
				ReplacedBy:   "new",
				Keys:         []KeyMetadata{{KeyName: "k", Source: SourceConfig{Kind: "gsm"}, GSM: gsm("old-k", "1")}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.meta.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := ParseMetadata(out)
			if err != nil {
				t.Fatalf("ParseMetadata: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(*got, tt.meta) {
				t.Errorf("round trip changed the value\n got: %+v\nwant: %+v\nyaml:\n%s", *got, tt.meta, out)
			}
		})
	}
}

// The format contract for existing repos: rewriting a file may only re-quote
// scalars and sort computed params. Anything else is a whole-file diff in a
// user's git history and must be a deliberate decision.
func TestMarshal_FixtureCompat(t *testing.T) {
	canonical := func(data []byte) []string {
		lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(data), `"`, "")), "\n")
		slices.Sort(lines)
		return lines
	}
	for _, path := range fixturePaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			m, err := ParseMetadata(original)
			if err != nil {
				t.Fatalf("ParseMetadata: %v", err)
			}
			written, err := m.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !slices.Equal(canonical(original), canonical(written)) {
				t.Errorf("rewrite changed more than quoting and param order:\n%s", written)
			}

			// A second write must be a no-op.
			reparsed, err := ParseMetadata(written)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			again, err := reparsed.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(written, again) {
				t.Errorf("Marshal is not idempotent:\nfirst:\n%s\nsecond:\n%s", written, again)
			}
		})
	}
}
