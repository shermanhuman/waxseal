package template

import (
	"testing"
)

func TestPayloadCompute(t *testing.T) {
	tests := []struct {
		name     string
		template string
		values   map[string]string
		secret   string
		want     string
	}{
		{
			name:     "PostgreSQL connection string",
			template: "postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
			values: map[string]string{
				"username": "myapp",
				"host":     "db.example.com",
				"port":     "5432",
				"database": "mydb",
			},
			secret: "s3cr3t",
			want:   "postgresql://myapp:s3cr3t@db.example.com:5432/mydb",
		},
		{
			name:     "MySQL connection string",
			template: "mysql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
			values: map[string]string{
				"username": "root",
				"host":     "localhost",
				"port":     "3306",
				"database": "test",
			},
			secret: "pa$$w0rd",
			want:   "mysql://root:pa$$w0rd@localhost:3306/test",
		},
		{
			name:     "Redis with just secret",
			template: "redis://:{{secret}}@{{host}}:{{port}}/{{db}}",
			values: map[string]string{
				"host": "redis.example.com",
				"port": "6379",
				"db":   "0",
			},
			secret: "redispass",
			want:   "redis://:redispass@redis.example.com:6379/0",
		},
		{
			name:     "API key only",
			template: "{{secret}}",
			values:   map[string]string{},
			secret:   "api-key-12345",
			want:     "api-key-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPayload(tt.template, tt.values, tt.secret, nil)
			if err != nil {
				t.Fatalf("NewPayload() error = %v", err)
			}
			if p.Computed != tt.want {
				t.Errorf("Computed = %q, want %q", p.Computed, tt.want)
			}
		})
	}
}

func TestParsePayload(t *testing.T) {
	jsonData := []byte(`{
		"schemaVersion": 1,
		"type": "templated",
		"template": "postgresql://{{username}}:{{secret}}@{{host}}/{{db}}",
		"values": {"username": "user", "host": "localhost", "db": "test"},
		"secret": "pass123",
		"computed": "postgresql://user:pass123@localhost/test"
	}`)

	p, err := ParsePayload(jsonData)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}

	if p.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", p.SchemaVersion)
	}
	if p.Type != "templated" {
		t.Errorf("Type = %s, want templated", p.Type)
	}
	if p.Secret != "pass123" {
		t.Errorf("Secret = %s, want pass123", p.Secret)
	}
}

func TestPayloadValidate(t *testing.T) {
	// Valid: has {{secret}} and all other vars in values
	p := &Payload{
		SchemaVersion: 1,
		Type:          "templated",
		Template:      "postgresql://{{username}}:{{secret}}@{{host}}/{{db}}",
		Values: map[string]string{
			"username": "user",
			"host":     "localhost",
			"db":       "test",
		},
		Secret:    "pass",
		Generator: &GeneratorConfig{Kind: "randomBase64", Bytes: 32},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	// Invalid: missing variable
	p.Values = map[string]string{"username": "user"}
	if err := p.Validate(); err == nil {
		t.Error("Validate() expected error for missing variable")
	}
}

func TestPayloadUpdateSecret(t *testing.T) {
	p, err := NewPayload(
		"postgresql://{{username}}:{{secret}}@{{host}}/{{database}}",
		map[string]string{
			"username": "myapp",
			"host":     "db.example.com",
			"database": "mydb",
		},
		"oldpass",
		nil,
	)
	if err != nil {
		t.Fatalf("NewPayload() error = %v", err)
	}

	if p.Computed != "postgresql://myapp:oldpass@db.example.com/mydb" {
		t.Fatalf("initial Computed = %q", p.Computed)
	}

	if err := p.UpdateSecret("newpass"); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	if p.Secret != "newpass" {
		t.Errorf("Secret = %q, want newpass", p.Secret)
	}
	if p.Computed != "postgresql://myapp:newpass@db.example.com/mydb" {
		t.Errorf("Computed = %q, want postgresql://myapp:newpass@db.example.com/mydb", p.Computed)
	}
}

func TestPayloadMarshal(t *testing.T) {
	p, _ := NewPayload(
		"postgresql://{{username}}:{{secret}}@{{host}}/{{db}}",
		map[string]string{"username": "user", "host": "localhost", "db": "test"},
		"pass123",
		&GeneratorConfig{Kind: "randomBase64", Bytes: 32},
	)

	data, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Parse it back
	p2, err := ParsePayload(data)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}

	if p2.Template != p.Template {
		t.Errorf("Template mismatch after round-trip")
	}
	if p2.Secret != p.Secret {
		t.Errorf("Secret mismatch after round-trip")
	}
}
