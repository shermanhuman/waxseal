package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
)

func TestConfig_NotInitialised(t *testing.T) {
	if _, err := newRepo(t).Config(); !core.IsNotFound(err) {
		t.Errorf("got %v, want not found", err)
	}
}

func TestWriteConfig_RejectsInvalid(t *testing.T) {
	r := newRepo(t)
	if err := r.WriteConfig(&config.Config{Version: "1"}); err == nil {
		t.Fatal("expected an error for a config without a store")
	}
	if _, err := os.Stat(r.ConfigPath()); !os.IsNotExist(err) {
		t.Error("a rejected config must not be written")
	}
}

// Reminders used to be configured by appending text to the config, guarded by
// strings.Contains("reminders:"). The generated config contains a commented
// reminders block, so the guard always matched and the file could never be
// updated. Configuring is now load, set, write.
func TestWriteConfig_UpdatesRemindersInGeneratedConfig(t *testing.T) {
	r := newRepo(t)
	generated := `# waxseal configuration
version: "1"

store:
  kind: gsm
  projectId: my-project

controller:
  namespace: kube-system
  serviceName: sealed-secrets

# Reminders (optional):
# reminders:
#   enabled: true
#   provider: google-calendar
`
	if err := os.MkdirAll(filepath.Dir(r.ConfigPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.ConfigPath(), []byte(generated), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := r.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	cfg.Reminders = &config.RemindersConfig{Enabled: true, Provider: "calendar", CalendarID: "team@example.com", LeadTimeDays: []int{14, 2}}
	if err := r.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	// And again, now that a real reminders block exists.
	cfg, err = r.Config()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	cfg.Reminders.Provider = "both"
	if err := r.WriteConfig(cfg); err != nil {
		t.Fatalf("second WriteConfig: %v", err)
	}

	got, err := r.Config()
	if err != nil {
		t.Fatalf("final reload: %v", err)
	}
	if got.Reminders == nil || got.Reminders.Provider != "both" || got.Reminders.CalendarID != "team@example.com" {
		t.Errorf("reminders = %+v", got.Reminders)
	}
	if got.Store.ProjectID != "my-project" {
		t.Errorf("projectId = %q, want it preserved", got.Store.ProjectID)
	}
	assertNoTempFiles(t, r.Root())
}
