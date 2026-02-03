// Package config handles loading and validation of waxseal configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/core"
	"sigs.k8s.io/yaml"
)

// Config represents the waxseal configuration from .waxseal/config.yaml
type Config struct {
	Version    string           `json:"version"`
	Store      StoreConfig      `json:"store"`
	Controller ControllerConfig `json:"controller,omitempty"`
	Cert       CertConfig       `json:"cert,omitempty"`
	Discovery  DiscoveryConfig  `json:"discovery,omitempty"`
	Bootstrap  BootstrapConfig  `json:"bootstrap,omitempty"`
	Reminders  *RemindersConfig `json:"reminders,omitempty"`
}

// StoreConfig configures the secret store backend.
type StoreConfig struct {
	Kind               string            `json:"kind"` // "gsm" for v1
	ProjectID          string            `json:"projectId"`
	DefaultReplication string            `json:"defaultReplication,omitempty"` // "automatic" or "user-managed"
	Labels             map[string]string `json:"labels,omitempty"`
}

// ControllerConfig configures Sealed Secrets controller discovery.
type ControllerConfig struct {
	Namespace      string `json:"namespace,omitempty"`      // default: "kube-system"
	ServiceName    string `json:"serviceName,omitempty"`    // default: "sealed-secrets"
	KeySecretLabel string `json:"keySecretLabel,omitempty"` // default: "sealedsecrets.bitnami.com/sealed-secrets-key"
}

// CertConfig configures certificate handling.
type CertConfig struct {
	RepoCertPath         string `json:"repoCertPath,omitempty"`         // default: "keys/pub-cert.pem"
	VerifyAgainstCluster bool   `json:"verifyAgainstCluster,omitempty"` // default: true
}

// DiscoveryConfig configures manifest discovery.
type DiscoveryConfig struct {
	IncludeGlobs []string `json:"includeGlobs,omitempty"` // default: ["apps/**/*.yaml"]
	ExcludeGlobs []string `json:"excludeGlobs,omitempty"`
}

// BootstrapConfig configures cluster bootstrap behavior.
type BootstrapConfig struct {
	Cluster ClusterConfig `json:"cluster,omitempty"`
}

// ClusterConfig configures cluster access for bootstrap.
type ClusterConfig struct {
	Enabled             bool   `json:"enabled,omitempty"`
	KubeContext         string `json:"kubeContext,omitempty"`
	AllowReadingSecrets bool   `json:"allowReadingSecrets,omitempty"`
}

// RemindersConfig configures expiration reminders.
type RemindersConfig struct {
	Enabled            bool        `json:"enabled"`
	Provider           string      `json:"provider,omitempty"`           // "tasks" (default), "calendar", "both", "none"
	CalendarID         string      `json:"calendarId,omitempty"`         // For calendar provider, default: "primary"
	TasklistID         string      `json:"tasklistId,omitempty"`         // For tasks provider, default: "@default"
	LeadTimeDays       []int       `json:"leadTimeDays,omitempty"`       // default: [30, 7, 1]
	EventTitleTemplate string      `json:"eventTitleTemplate,omitempty"` // default template
	Auth               *AuthConfig `json:"auth,omitempty"`
}

// AuthConfig configures authentication for reminder providers.
type AuthConfig struct {
	Kind string `json:"kind"` // "adc" for v1
}

// Load reads and parses a config file, applying defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.WrapNotFound(path, err)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	return Parse(data)
}

// Parse parses config from YAML bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config

	// Use strict unmarshaling to reject unknown fields
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return nil, core.WrapValidation("config", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	cfg.applyDefaults()
	return &cfg, nil
}

// Validate checks the config for required fields and valid values.
func (c *Config) Validate() error {
	if c.Version == "" {
		return core.NewValidationError("version", "required")
	}

	if c.Store.Kind == "" {
		return core.NewValidationError("store.kind", "required")
	}

	if c.Store.Kind != "gsm" {
		return core.NewValidationError("store.kind", "must be 'gsm' (only supported backend in v1)")
	}

	if c.Store.ProjectID == "" {
		return core.NewValidationError("store.projectId", "required")
	}

	if c.Store.DefaultReplication != "" &&
		c.Store.DefaultReplication != "automatic" &&
		c.Store.DefaultReplication != "user-managed" {
		return core.NewValidationError("store.defaultReplication", "must be 'automatic' or 'user-managed'")
	}

	if c.Reminders != nil && c.Reminders.Enabled {
		if c.Reminders.Auth == nil {
			return core.NewValidationError("reminders.auth", "required when reminders enabled")
		}
		if c.Reminders.Auth.Kind != "adc" {
			return core.NewValidationError("reminders.auth.kind", "must be 'adc' (only supported in v1)")
		}
	}

	return nil
}

func (c *Config) applyDefaults() {
	// Controller defaults
	if c.Controller.Namespace == "" {
		c.Controller.Namespace = "kube-system"
	}
	if c.Controller.ServiceName == "" {
		c.Controller.ServiceName = "sealed-secrets"
	}
	if c.Controller.KeySecretLabel == "" {
		c.Controller.KeySecretLabel = "sealedsecrets.bitnami.com/sealed-secrets-key"
	}

	// Cert defaults
	if c.Cert.RepoCertPath == "" {
		c.Cert.RepoCertPath = "keys/pub-cert.pem"
	}
	// Note: VerifyAgainstCluster defaults to false (Go zero value)
	// The plan says default true, but we handle that at usage time

	// Discovery defaults
	if len(c.Discovery.IncludeGlobs) == 0 {
		c.Discovery.IncludeGlobs = []string{"apps/**/*.yaml"}
	}

	// Reminders defaults
	if c.Reminders != nil && c.Reminders.Enabled {
		if c.Reminders.Provider == "" {
			c.Reminders.Provider = "tasks" // Tasks is default - auto-appears in Calendar
		}
		if c.Reminders.CalendarID == "" {
			c.Reminders.CalendarID = "primary"
		}
		if c.Reminders.TasklistID == "" {
			c.Reminders.TasklistID = "@default" // User's primary task list
		}
		if len(c.Reminders.LeadTimeDays) == 0 {
			c.Reminders.LeadTimeDays = []int{30, 7, 1}
		}
	}
}

// DefaultConfigPath returns the default config path relative to a repo root.
func DefaultConfigPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".waxseal", "config.yaml")
}
