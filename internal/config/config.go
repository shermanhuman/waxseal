// Package config handles loading and validation of waxseal configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shermanhuman/waxseal/internal/core"
	"go.yaml.in/yaml/v3"
)

// Config represents the waxseal configuration from .waxseal/config.yaml
//
// Fields marked Deprecated were specified but never read by any command. They
// are still accepted so existing config files parse, and are dropped by
// Marshal the next time waxseal writes the file.
type Config struct {
	Version    string           `json:"version" yaml:"version"`
	Store      StoreConfig      `json:"store" yaml:"store"`
	Controller ControllerConfig `json:"controller,omitempty" yaml:"controller,omitempty"`
	Cert       CertConfig       `json:"cert,omitempty" yaml:"cert,omitempty"`
	Discovery  DiscoveryConfig  `json:"discovery,omitempty" yaml:"discovery,omitempty"`
	Bootstrap  BootstrapConfig  `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty"`
	Reminders  *RemindersConfig `json:"reminders,omitempty" yaml:"reminders,omitempty"`
}

// StoreConfig configures the secret store backend.
type StoreConfig struct {
	Kind               string            `json:"kind" yaml:"kind"` // "gsm" for v1
	ProjectID          string            `json:"projectId" yaml:"projectId"`
	DefaultReplication string            `json:"defaultReplication,omitempty" yaml:"defaultReplication,omitempty"` // "automatic" or "user-managed"
	Labels             map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// ControllerConfig configures Sealed Secrets controller discovery.
type ControllerConfig struct {
	Namespace      string `json:"namespace,omitempty" yaml:"namespace,omitempty"`           // default: "kube-system"
	ServiceName    string `json:"serviceName,omitempty" yaml:"serviceName,omitempty"`       // default: "sealed-secrets"
	KeySecretLabel string `json:"keySecretLabel,omitempty" yaml:"keySecretLabel,omitempty"` // default: "sealedsecrets.bitnami.com/sealed-secrets-key"
}

// CertConfig configures certificate handling.
type CertConfig struct {
	RepoCertPath         string `json:"repoCertPath,omitempty" yaml:"repoCertPath,omitempty"`                 // default: "keys/pub-cert.pem"
	VerifyAgainstCluster bool   `json:"verifyAgainstCluster,omitempty" yaml:"verifyAgainstCluster,omitempty"` // default: true
}

// DiscoveryConfig is unused.
//
// Deprecated: never read; see Config.
type DiscoveryConfig struct {
	IncludeGlobs []string `json:"includeGlobs,omitempty" yaml:"includeGlobs,omitempty"` // default: ["apps/**/*.yaml"]
	ExcludeGlobs []string `json:"excludeGlobs,omitempty" yaml:"excludeGlobs,omitempty"`
}

// BootstrapConfig is unused.
//
// Deprecated: never read; see Config.
type BootstrapConfig struct {
	Cluster ClusterConfig `json:"cluster,omitempty" yaml:"cluster,omitempty"`
}

// ClusterConfig configures cluster access for bootstrap.
type ClusterConfig struct {
	Enabled             bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	KubeContext         string `json:"kubeContext,omitempty" yaml:"kubeContext,omitempty"`
	AllowReadingSecrets bool   `json:"allowReadingSecrets,omitempty" yaml:"allowReadingSecrets,omitempty"`
}

// RemindersConfig configures expiration reminders.
type RemindersConfig struct {
	Enabled            bool        `json:"enabled" yaml:"enabled"`
	Provider           string      `json:"provider,omitempty" yaml:"provider,omitempty"`                     // "tasks" (default), "calendar", "both", "none"
	CalendarID         string      `json:"calendarId,omitempty" yaml:"calendarId,omitempty"`                 // For calendar provider, default: "primary"
	TasklistID         string      `json:"tasklistId,omitempty" yaml:"tasklistId,omitempty"`                 // For tasks provider, default: "@default"
	LeadTimeDays       []int       `json:"leadTimeDays,omitempty" yaml:"leadTimeDays,omitempty"`             // default: [30, 7, 1]
	EventTitleTemplate string      `json:"eventTitleTemplate,omitempty" yaml:"eventTitleTemplate,omitempty"` // default template
	Auth               *AuthConfig `json:"auth,omitempty" yaml:"auth,omitempty"`
}

// AuthConfig is unused; reminders always authenticate with ADC.
//
// Deprecated: never read; see Config.
type AuthConfig struct {
	Kind string `json:"kind" yaml:"kind"` // "adc" for v1
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

	// Reject unknown fields
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
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

	if r := c.Reminders; r != nil && r.Enabled && r.Provider != "" {
		if err := core.ReminderProviders.Validate("reminders.provider", r.Provider); err != nil {
			return err
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

	// Cert defaults
	if c.Cert.RepoCertPath == "" {
		c.Cert.RepoCertPath = "keys/pub-cert.pem"
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

// Marshal renders the config as YAML through the same struct tags Parse uses.
// Deprecated fields are dropped. Comments in an existing file do not survive.
func (c *Config) Marshal() ([]byte, error) {
	out := *c
	out.Store.DefaultReplication = ""
	out.Store.Labels = nil
	out.Controller.KeySecretLabel = ""
	out.Cert.VerifyAgainstCluster = false
	out.Discovery = DiscoveryConfig{}
	out.Bootstrap = BootstrapConfig{}
	if c.Reminders != nil {
		r := *c.Reminders
		r.EventTitleTemplate = ""
		r.Auth = nil
		out.Reminders = &r
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&out); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return buf.Bytes(), nil
}
