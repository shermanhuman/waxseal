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
	}{
		{
			"postgresql://admin:s3cret@db.internal:5432/app?sslmode=require",
			"postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}?sslmode=require",
			map[string]string{"username": "admin", "host": "db.internal", "port": "5432", "database": "app"},
		},
		{
			"redis://:pw@cache:6379",
			"redis://:{{secret}}@{{host}}:{{port}}",
			map[string]string{"host": "cache", "port": "6379"},
		},
		{"not a url", "", nil},
		{"https://example.com/page", "", nil}, // not a database scheme
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			ok, tmpl, values := DetectConnectionString(tt.value, nil)
			if ok != (tt.wantTmpl != "") || tmpl != tt.wantTmpl || !reflect.DeepEqual(values, tt.wantValues) {
				t.Errorf("got ok=%v tmpl=%q values=%v", ok, tmpl, values)
			}
		})
	}
}
