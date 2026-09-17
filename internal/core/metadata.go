// Package core defines domain types and interfaces for waxseal.
package core

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"
)

// SecretMetadata represents the metadata for a SealedSecret.
// Stored in .waxseal/metadata/<shortName>.yaml
type SecretMetadata struct {
	ShortName    string          `json:"shortName" yaml:"shortName"`
	ManifestPath string          `json:"manifestPath" yaml:"manifestPath"`
	SealedSecret SealedSecretRef `json:"sealedSecret" yaml:"sealedSecret"`
	Status       string          `json:"status,omitempty" yaml:"status,omitempty"`       // "active" or "retired"
	RetiredAt    string          `json:"retiredAt,omitempty" yaml:"retiredAt,omitempty"` // RFC3339
	RetireReason string          `json:"retireReason,omitempty" yaml:"retireReason,omitempty"`
	ReplacedBy   string          `json:"replacedBy,omitempty" yaml:"replacedBy,omitempty"`
	Keys         []KeyMetadata   `json:"keys" yaml:"keys"`
}

// SealedSecretRef identifies a SealedSecret.
type SealedSecretRef struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Scope     string `json:"scope" yaml:"scope"`                   // "strict", "namespace-wide", "cluster-wide"
	Type      string `json:"type,omitempty" yaml:"type,omitempty"` // e.g., "kubernetes.io/dockerconfigjson"
}

// KeyMetadata describes a single key within a secret.
type KeyMetadata struct {
	KeyName       string          `json:"keyName" yaml:"keyName"`
	Source        SourceConfig    `json:"source" yaml:"source"`
	GSM           *GSMRef         `json:"gsm,omitempty" yaml:"gsm,omitempty"`
	Rotation      *RotationConfig `json:"rotation,omitempty" yaml:"rotation,omitempty"`
	Expiry        *ExpiryConfig   `json:"expiry,omitempty" yaml:"expiry,omitempty"`
	OperatorHints *OperatorHints  `json:"operatorHints,omitempty" yaml:"operatorHints,omitempty"`
	Computed      *ComputedConfig `json:"computed,omitempty" yaml:"computed,omitempty"`
}

// SourceConfig specifies where a key's value comes from.
type SourceConfig struct {
	Kind string `json:"kind" yaml:"kind"` // "gsm" or "computed"
}

// GSMRef references a secret in Google Secret Manager.
type GSMRef struct {
	SecretResource string `json:"secretResource" yaml:"secretResource"` // "projects/<project>/secrets/<secretId>"
	Version        string `json:"version" yaml:"version"`               // Must be numeric
}

// RotationConfig describes how a key is rotated.
type RotationConfig struct {
	Mode      string           `json:"mode" yaml:"mode"` // "static", "generated", "external", "unknown"
	Generator *GeneratorConfig `json:"generator,omitempty" yaml:"generator,omitempty"`
}

// GeneratorConfig describes how to generate a key value.
type GeneratorConfig struct {
	Kind  string `json:"kind" yaml:"kind"`                       // "randomBase64", "randomHex", "randomBytes"
	Bytes int    `json:"bytes,omitempty" yaml:"bytes,omitempty"` // Number of random bytes to generate
}

// ExpiryConfig tracks key expiration.
type ExpiryConfig struct {
	ExpiresAt string `json:"expiresAt" yaml:"expiresAt"` // RFC3339
}

// OperatorHints references guidance for manual rotation stored in GSM.
// Per plan: "Keep rotation URLs, runbook notes, and other guidance out of Git."
// All hint content lives in GSM as JSON; metadata only contains the GSM reference.
type OperatorHints struct {
	// GSM reference to the hints payload (required)
	GSM *GSMRef `json:"gsm" yaml:"gsm"`
	// Format of the GSM payload (required, must be "json")
	Format string `json:"format" yaml:"format"`
}

// GSMHintsPayload is the schema for operator hints stored in GSM.
// This is stored as JSON in the GSM secret, not in Git metadata.
type GSMHintsPayload struct {
	SchemaVersion int           `json:"schemaVersion"`
	Links         []GSMHintLink `json:"links,omitempty"`
	Notes         string        `json:"notes,omitempty"`
}

// GSMHintLink is a labeled URL in the hints payload.
type GSMHintLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// ComputedConfig describes how to compute a key from other values.
type ComputedConfig struct {
	Kind     string            `json:"kind" yaml:"kind"` // "template"
	Template string            `json:"template" yaml:"template"`
	GSM      *GSMRef           `json:"gsm,omitempty" yaml:"gsm,omitempty"` // GSM reference for JSON payload (new architecture)
	Inputs   []InputRef        `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Params   map[string]string `json:"params,omitempty" yaml:"params,omitempty"`
}

// InputRef references a value from another key.
type InputRef struct {
	Var string `json:"var" yaml:"var"` // Template variable name
	Ref KeyRef `json:"ref" yaml:"ref"`
}

// KeyRef references a specific key.
type KeyRef struct {
	ShortName string `json:"shortName,omitempty" yaml:"shortName,omitempty"` // Default: current secret
	KeyName   string `json:"keyName" yaml:"keyName"`
}

// ParseMetadata parses metadata from YAML bytes with strict validation.
// Unknown fields are rejected.
func ParseMetadata(data []byte) (*SecretMetadata, error) {
	var m SecretMetadata
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, WrapValidation("metadata", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Marshal renders metadata as YAML. It is the inverse of ParseMetadata:
// both go through the same struct tags, so a field cannot be parsed but
// forgotten on write. Fields appear in struct order.
func (m *SecretMetadata) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return buf.Bytes(), nil
}

// Validate checks the metadata for required fields and valid values.
func (m *SecretMetadata) Validate() error {
	if m.ShortName == "" {
		return NewValidationError("shortName", "required")
	}
	if m.ManifestPath == "" {
		return NewValidationError("manifestPath", "required")
	}
	if err := m.SealedSecret.Validate(); err != nil {
		return err
	}
	if m.Status != "" && m.Status != "active" && m.Status != "retired" {
		return NewValidationError("status", "must be 'active' or 'retired'")
	}
	if len(m.Keys) == 0 {
		return NewValidationError("keys", "at least one key required")
	}
	for i, k := range m.Keys {
		if err := k.Validate(); err != nil {
			return WrapValidation(fmt.Sprintf("keys[%d]", i), err)
		}
	}
	return nil
}

// Validate checks the SealedSecretRef.
func (s *SealedSecretRef) Validate() error {
	if s.Name == "" {
		return NewValidationError("sealedSecret.name", "required")
	}
	if s.Namespace == "" {
		return NewValidationError("sealedSecret.namespace", "required")
	}
	validScopes := map[string]bool{"strict": true, "namespace-wide": true, "cluster-wide": true}
	if !validScopes[s.Scope] {
		return NewValidationError("sealedSecret.scope", "must be 'strict', 'namespace-wide', or 'cluster-wide'")
	}
	return nil
}

// Validate checks the KeyMetadata.
func (k *KeyMetadata) Validate() error {
	if k.KeyName == "" {
		return NewValidationError("keyName", "required")
	}
	if k.Source.Kind != "gsm" && k.Source.Kind != "computed" {
		return NewValidationError("source.kind", "must be 'gsm' or 'computed'")
	}
	if k.Source.Kind == "gsm" {
		if k.GSM == nil {
			return NewValidationError("gsm", "required when source.kind is 'gsm'")
		}
		if err := k.GSM.Validate(); err != nil {
			return err
		}
		if k.Rotation != nil {
			if err := k.Rotation.Validate(); err != nil {
				return err
			}
		}
	}
	if k.Source.Kind == "computed" {
		if k.Computed == nil {
			return NewValidationError("computed", "required when source.kind is 'computed'")
		}
		if err := k.Computed.Validate(); err != nil {
			return err
		}
	}
	if k.Expiry != nil {
		if err := k.Expiry.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// numericVersionRegex matches numeric GSM versions only.
var numericVersionRegex = regexp.MustCompile(`^[0-9]+$`)

// Validate checks the GSMRef.
func (g *GSMRef) Validate() error {
	if g.SecretResource == "" {
		return NewValidationError("gsm.secretResource", "required")
	}
	if g.Version == "" {
		return NewValidationError("gsm.version", "required")
	}
	// GSM aliases like "latest" are NOT allowed - must be numeric
	if !numericVersionRegex.MatchString(g.Version) {
		return NewValidationError("gsm.version", "must be numeric (aliases like 'latest' are not supported)")
	}
	return nil
}

// Validate checks the RotationConfig.
func (r *RotationConfig) Validate() error {
	validModes := map[string]bool{"static": true, "generated": true, "external": true, "unknown": true}
	if !validModes[r.Mode] {
		return NewValidationError("rotation.mode", "must be 'static', 'generated', 'external', or 'unknown'")
	}
	if r.Mode == "generated" && r.Generator == nil {
		return NewValidationError("rotation.generator", "required when mode is 'generated'")
	}
	if r.Generator != nil {
		validKinds := map[string]bool{"randomBase64": true, "randomHex": true, "randomBytes": true}
		if !validKinds[r.Generator.Kind] {
			return NewValidationError("rotation.generator.kind", "must be 'randomBase64', 'randomHex', or 'randomBytes'")
		}
	}
	return nil
}

// Validate checks the ExpiryConfig.
func (e *ExpiryConfig) Validate() error {
	if e.ExpiresAt == "" {
		return NewValidationError("expiry.expiresAt", "required")
	}
	if _, err := time.Parse(time.RFC3339, e.ExpiresAt); err != nil {
		return NewValidationError("expiry.expiresAt", "must be RFC3339 format")
	}
	return nil
}

// Validate checks the ComputedConfig.
func (c *ComputedConfig) Validate() error {
	if c.Kind != "template" {
		return NewValidationError("computed.kind", "must be 'template'")
	}
	if c.Template == "" {
		return NewValidationError("computed.template", "required")
	}
	return nil
}

// IsRetired returns true if the secret is retired.
func (m *SecretMetadata) IsRetired() bool {
	return m.Status == "retired"
}

// IsExpired returns true if any key is expired.
func (m *SecretMetadata) IsExpired() bool {
	now := time.Now()
	for _, k := range m.Keys {
		if k.Expiry != nil {
			if exp, err := time.Parse(time.RFC3339, k.Expiry.ExpiresAt); err == nil {
				if exp.Before(now) {
					return true
				}
			}
		}
	}
	return false
}

// ExpiresWithinDays returns true if any key expires within the given days.
func (m *SecretMetadata) ExpiresWithinDays(days int) bool {
	threshold := time.Now().AddDate(0, 0, days)
	for _, k := range m.Keys {
		if k.Expiry != nil {
			if exp, err := time.Parse(time.RFC3339, k.Expiry.ExpiresAt); err == nil {
				if exp.Before(threshold) {
					return true
				}
			}
		}
	}
	return false
}
