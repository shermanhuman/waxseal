package computed

import (
	"reflect"
	"testing"
)

func TestDetectConnectionString(t *testing.T) {
	tests := []struct {
		value      string
		wantTmpl   string
		wantValues map[string]string
		wantSecret string
	}{
		{
			"postgresql://admin:s3cret@db.internal:5432/app?sslmode=require",
			"postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}?sslmode=require",
			map[string]string{"username": "admin", "host": "db.internal", "port": "5432", "database": "app"},
			"s3cret",
		},
		{
			"redis://:pw@cache:6379",
			"redis://:{{secret}}@{{host}}:{{port}}",
			map[string]string{"host": "cache", "port": "6379"},
			"pw",
		},
		// A percent-encoded password must not leak into the template, and
		// rendering must reproduce the original string byte for byte.
		{
			"postgres://app:p%40ss%3Aword@db:5432/prod",
			"postgres://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
			map[string]string{"username": "app", "host": "db", "port": "5432", "database": "prod"},
			"p%40ss%3Aword",
		},
		// A password that also appears elsewhere in the URL.
		{
			"mongodb://db:db@db:27017/db",
			"mongodb://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
			map[string]string{"username": "db", "host": "db", "port": "27017", "database": "db"},
			"db",
		},
		{"not a url", "", nil, ""},
		{"https://user:pw@example.com/page", "", nil, ""}, // not a database scheme
		{"postgres://user@db/app", "", nil, ""},           // no password: nothing to rotate
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			tmpl, values, secret, ok := DetectConnectionString(tt.value)
			if ok != (tt.wantTmpl != "") || tmpl != tt.wantTmpl || !reflect.DeepEqual(values, tt.wantValues) || secret != tt.wantSecret {
				t.Errorf("got ok=%v tmpl=%q values=%v secret=%q", ok, tmpl, values, secret)
			}
			if ok {
				p := &Payload{Template: tmpl, Values: values, Secret: secret}
				if rendered, _ := p.Compute(); rendered != tt.value {
					t.Errorf("template does not reproduce the value: %q", rendered)
				}
			}
		})
	}
}
