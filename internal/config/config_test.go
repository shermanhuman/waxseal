package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shermanhuman/waxseal/internal/core"
)

func TestParse_ValidConfig(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("version = %q, want %q", cfg.Version, "1")
	}
	if cfg.Store.Kind != "gsm" {
		t.Errorf("store.kind = %q, want %q", cfg.Store.Kind, "gsm")
	}
	if cfg.Store.ProjectID != "my-project" {
		t.Errorf("store.projectId = %q, want %q", cfg.Store.ProjectID, "my-project")
	}
}

func TestParse_AppliesDefaults(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Controller defaults
	if cfg.Controller.Namespace != "kube-system" {
		t.Errorf("controller.namespace = %q, want %q", cfg.Controller.Namespace, "kube-system")
	}
	if cfg.Controller.ServiceName != "sealed-secrets" {
		t.Errorf("controller.serviceName = %q, want %q", cfg.Controller.ServiceName, "sealed-secrets")
	}

	// Cert defaults
	if cfg.Cert.RepoCertPath != "keys/pub-cert.pem" {
		t.Errorf("cert.repoCertPath = %q, want %q", cfg.Cert.RepoCertPath, "keys/pub-cert.pem")
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
unknownField: value
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestParse_MissingVersion(t *testing.T) {
	yaml := `
store:
  kind: gsm
  projectId: my-project
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.Is(err, core.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestParse_MissingStoreKind(t *testing.T) {
	yaml := `
version: "1"
store:
  projectId: my-project
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing store.kind")
	}
}

func TestParse_UnsupportedStoreKind(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: vault
  projectId: my-project
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unsupported store.kind")
	}
}

func TestParse_MissingProjectID(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing store.projectId")
	}
}

func TestParse_RemindersWithAuth(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
reminders:
  enabled: true
  auth:
    kind: adc
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if !cfg.Reminders.Enabled {
		t.Error("reminders.enabled should be true")
	}
	if cfg.Reminders.Provider != "tasks" {
		t.Errorf("reminders.provider = %q, want %q", cfg.Reminders.Provider, "tasks")
	}
	if cfg.Reminders.CalendarID != "primary" {
		t.Errorf("reminders.calendarId = %q, want %q", cfg.Reminders.CalendarID, "primary")
	}
	if cfg.Reminders.TasklistID != "@default" {
		t.Errorf("reminders.tasklistId = %q, want %q", cfg.Reminders.TasklistID, "@default")
	}
}

func TestParse_RemindersEnabledWithoutAuth(t *testing.T) {
	// reminders.auth carried no information (ADC was the only legal value)
	// and is no longer required.
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
reminders:
  enabled: true
`
	if _, err := Parse([]byte(yaml)); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
}

func TestParse_InvalidReminderProvider(t *testing.T) {
	yaml := `
version: "1"
store:
  kind: gsm
  projectId: my-project
reminders:
  enabled: true
  provider: google-calendar
`
	if _, err := Parse([]byte(yaml)); err == nil {
		t.Fatal("expected error for an unknown reminders provider")
	}
}

// A config written by an older waxseal must keep loading, and the fields no
// command ever read must disappear the next time the file is written.
func TestMarshal_DropsDeprecatedFields(t *testing.T) {
	old := `
version: "1"
store:
  kind: gsm
  projectId: my-project
  defaultReplication: automatic
  labels:
    team: platform
controller:
  namespace: sealed-secrets
  serviceName: controller
  keySecretLabel: sealedsecrets.bitnami.com/sealed-secrets-key
cert:
  repoCertPath: keys/pub-cert.pem
  verifyAgainstCluster: true
discovery:
  includeGlobs: ["apps/**/*.yaml"]
  excludeGlobs: ["**/kustomization.yaml"]
bootstrap:
  cluster:
    enabled: true
    kubeContext: prod
    allowReadingSecrets: true
reminders:
  enabled: true
  provider: both
  leadTimeDays: [14, 3]
  eventTitleTemplate: "x"
  auth:
    kind: adc
`
	cfg, err := Parse([]byte(old))
	if err != nil {
		t.Fatalf("an existing config must still parse: %v", err)
	}
	out, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, gone := range []string{"defaultReplication", "labels", "keySecretLabel", "verifyAgainstCluster",
		"discovery", "bootstrap", "eventTitleTemplate", "auth"} {
		if strings.Contains(string(out), gone) {
			t.Errorf("deprecated field %q was written back:\n%s", gone, out)
		}
	}

	again, err := Parse(out)
	if err != nil {
		t.Fatalf("written config must parse: %v\n%s", err, out)
	}
	if again.Store.ProjectID != "my-project" || again.Controller.Namespace != "sealed-secrets" ||
		again.Controller.ServiceName != "controller" || again.Reminders.Provider != "both" ||
		len(again.Reminders.LeadTimeDays) != 2 || again.Reminders.LeadTimeDays[0] != 14 {
		t.Errorf("live fields did not survive the write:\n%s", out)
	}

	second, err := again.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(out) {
		t.Errorf("Marshal is not idempotent:\nfirst:\n%s\nsecond:\n%s", out, second)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, core.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
version: "1"
store:
  kind: gsm
  projectId: my-project
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Store.ProjectID != "my-project" {
		t.Errorf("store.projectId = %q, want %q", cfg.Store.ProjectID, "my-project")
	}
}
