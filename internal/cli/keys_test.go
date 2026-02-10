package cli

import (
	"testing"
)

func TestParseKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		wantKind string
		wantName string
		wantTmpl string
		wantMode string
		wantErr  bool
	}{
		{
			name:     "static key",
			spec:     "username",
			wantKind: "static",
			wantName: "username",
			wantMode: "static",
		},
		{
			name:     "random key",
			spec:     "password:random",
			wantKind: "random",
			wantName: "password",
			wantMode: "generated",
		},
		{
			name:     "templated key with prefix",
			spec:     "access-key:template=GK{{secret}}",
			wantKind: "template",
			wantName: "access-key",
			wantTmpl: "GK{{secret}}",
			wantMode: "generated",
		},
		{
			name:     "templated key with colons in connection string",
			spec:     "dsn:template=postgresql://user:{{secret}}@localhost/db",
			wantKind: "template",
			wantName: "dsn",
			wantTmpl: "postgresql://user:{{secret}}@localhost/db",
			wantMode: "generated",
		},
		{
			name:     "templated key with port colon in value",
			spec:     "url:template=postgresql://u:{{secret}}@h:5432/db",
			wantKind: "template",
			wantName: "url",
			wantTmpl: "postgresql://u:{{secret}}@h:5432/db",
			wantMode: "generated",
		},
		{
			name:    "empty spec",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "empty name",
			spec:    ":random",
			wantErr: true,
		},
		{
			name:    "template without secret placeholder",
			spec:    "key:template=prefix",
			wantErr: true,
		},
		{
			name:    "empty template",
			spec:    "key:template=",
			wantErr: true,
		},
		{
			name:    "unknown modifier",
			spec:    "key:unknown",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeySpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseKeySpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.Name != tt.wantName {
				t.Errorf("ParseKeySpec(%q).Name = %q, want %q", tt.spec, got.Name, tt.wantName)
			}
			if got.Kind != tt.wantKind {
				t.Errorf("ParseKeySpec(%q).Kind = %q, want %q", tt.spec, got.Kind, tt.wantKind)
			}
			if got.Template != tt.wantTmpl {
				t.Errorf("ParseKeySpec(%q).Template = %q, want %q", tt.spec, got.Template, tt.wantTmpl)
			}
			if got.RotationMode != tt.wantMode {
				t.Errorf("ParseKeySpec(%q).RotationMode = %q, want %q", tt.spec, got.RotationMode, tt.wantMode)
			}
		})
	}
}

func TestValidateGeneratorKind(t *testing.T) {
	tests := []struct {
		kind    string
		wantErr bool
	}{
		{"randomBase64", false},
		{"randomHex", false},
		{"random", true},
		{"base64", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			err := ValidateGeneratorKind(tt.kind)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGeneratorKind(%q) error = %v, wantErr %v", tt.kind, err, tt.wantErr)
			}
		})
	}
}

func TestBuildGeneratorConfig(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		bytes     int
		wantBytes int
		wantErr   bool
	}{
		{
			name:      "base64 with custom bytes",
			kind:      "randomBase64",
			bytes:     64,
			wantBytes: 64,
		},
		{
			name:      "hex with default bytes",
			kind:      "randomHex",
			bytes:     0, // should default to 32
			wantBytes: 32,
		},
		{
			name:    "invalid kind",
			kind:    "invalid",
			bytes:   32,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildGeneratorConfig(tt.kind, tt.bytes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BuildGeneratorConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.Kind != tt.kind {
				t.Errorf("BuildGeneratorConfig().Kind = %q, want %q", got.Kind, tt.kind)
			}
			if got.Bytes != tt.wantBytes {
				t.Errorf("BuildGeneratorConfig().Bytes = %d, want %d", got.Bytes, tt.wantBytes)
			}
		})
	}
}
