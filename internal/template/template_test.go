package template

import (
	"errors"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestParse_Valid(t *testing.T) {
	tmpl, err := Parse("postgresql://{{username}}:{{password}}@{{host}}:{{port}}/{{db}}")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	vars := tmpl.Variables()
	if len(vars) != 5 {
		t.Errorf("len(vars) = %d, want 5", len(vars))
	}

	expected := []string{"username", "password", "host", "port", "db"}
	for i, v := range expected {
		if i >= len(vars) || vars[i] != v {
			t.Errorf("vars[%d] = %q, want %q", i, vars[i], v)
		}
	}
}

func TestParse_Empty(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Fatal("expected error for empty template")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestParse_NoVariables(t *testing.T) {
	tmpl, err := Parse("static-string")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tmpl.Variables()) != 0 {
		t.Error("expected no variables")
	}
}

func TestParse_DuplicateVariables(t *testing.T) {
	tmpl, err := Parse("{{foo}}-{{foo}}-{{bar}}")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	vars := tmpl.Variables()
	if len(vars) != 2 {
		t.Errorf("len(vars) = %d, want 2 (duplicates removed)", len(vars))
	}
}

func TestTemplate_Execute(t *testing.T) {
	tmpl, _ := Parse("postgresql://{{username}}:{{password}}@localhost:5432/mydb")

	result, err := tmpl.Execute(map[string]string{
		"username": "admin",
		"password": "secret123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "postgresql://admin:secret123@localhost:5432/mydb"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestTemplate_Execute_MissingVariable(t *testing.T) {
	tmpl, _ := Parse("{{foo}}-{{bar}}-{{baz}}")

	_, err := tmpl.Execute(map[string]string{
		"foo": "value",
		// missing bar and baz
	})
	if err == nil {
		t.Fatal("expected error for missing variables")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplate_Execute_ExtraValues(t *testing.T) {
	tmpl, _ := Parse("{{foo}}")

	result, err := tmpl.Execute(map[string]string{
		"foo":   "value",
		"extra": "ignored",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result != "value" {
		t.Errorf("got %q, want %q", result, "value")
	}
}

func TestTemplate_Raw(t *testing.T) {
	raw := "{{foo}}-{{bar}}"
	tmpl, _ := Parse(raw)

	if tmpl.Raw() != raw {
		t.Errorf("Raw() = %q, want %q", tmpl.Raw(), raw)
	}
}

func TestValidateSyntax(t *testing.T) {
	tests := []struct {
		name     string
		template string
		wantErr  bool
	}{
		{"valid", "{{foo}}-{{bar}}", false},
		{"valid no vars", "static", false},
		{"unmatched open", "{{foo}-{{bar}}", true},
		{"unmatched close", "{{foo}}-bar}}", true},
		{"empty placeholder", "{{}}", true},
		{"nested braces", "{{{foo}}}", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSyntax(tt.template)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSyntax() = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTemplate_Execute_SpecialChars(t *testing.T) {
	// Test with special characters in values (like passwords)
	tmpl, _ := Parse("postgresql://{{user}}:{{pass}}@host/db")

	result, err := tmpl.Execute(map[string]string{
		"user": "admin",
		"pass": "p@ss!w0rd$",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	expected := "postgresql://admin:p@ss!w0rd$@host/db"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}
