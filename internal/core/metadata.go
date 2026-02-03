// Package core defines domain types and interfaces for waxseal.
package core

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"sigs.k8s.io/yaml"
)

// SecretMetadata represents the metadata for a SealedSecret.
// Stored in .waxseal/metadata/<shortName>.yaml
type SecretMetadata struct {
	ShortName    string          `json:"shortName"`
	ManifestPath string          `json:"manifestPath"`
	SealedSecret SealedSecretRef `json:"sealedSecret"`
	Status       string          `json:"status,omitempty"`    // "active" or "retired"
	RetiredAt    string          `json:"retiredAt,omitempty"` // RFC3339
	RetireReason string          `json:"retireReason,omitempty"`
	ReplacedBy   string          `json:"replacedBy,omitempty"`
	Keys         []KeyMetadata   `json:"keys"`
}

// SealedSecretRef identifies a SealedSecret.
type SealedSecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Scope     string `json:"scope"`          // "strict", "namespace-wide", "cluster-wide"
	Type      string `json:"type,omitempty"` // e.g., "kubernetes.io/dockerconfigjson"
}

// KeyMetadata describes a single key within a secret.
type KeyMetadata struct {
	KeyName       string          `json:"keyName"`
	Source        SourceConfig    `json:"source"`
	GSM           *GSMRef         `json:"gsm,omitempty"`
	Rotation      *RotationConfig `json:"rotation,omitempty"`
	Expiry        *ExpiryConfig   `json:"expiry,omitempty"`
	OperatorHints *OperatorHints  `json:"operatorHints,omitempty"`
	Computed      *ComputedConfig `json:"computed,omitempty"`
}

// SourceConfig specifies where a key's value comes from.
type SourceConfig struct {
	Kind string `json:"kind"` // "gsm" or "computed"
}

// GSMRef references a secret in Google Secret Manager.
type GSMRef struct {
	SecretResource string `json:"secretResource"` // "projects/<project>/secrets/<secretId>"
	Version        string `json:"version"`        // Must be numeric
	ETag           string `json:"etag,omitempty"`
}

// RotationConfig describes how a key is rotated.
type RotationConfig struct {
	Mode      string           `json:"mode"` // "generated", "external", "manual", "unknown"
	Generator *GeneratorConfig `json:"generator,omitempty"`
}

// GeneratorConfig describes how to generate a key value.
type GeneratorConfig struct {
	Kind  string `json:"kind"`            // "randomBase64", "randomHex", "randomBytes"
	Bytes int    `json:"bytes,omitempty"` // Number of bytes
	Chars int    `json:"chars,omitempty"` // Number of characters
}

// ExpiryConfig tracks key expiration.
type ExpiryConfig struct {
	ExpiresAt string `json:"expiresAt"`        // RFC3339
	Source    string `json:"source,omitempty"` // "vendor", "certificate", "policy", "unknown"
}

// OperatorHints provides guidance for manual rotation.
type OperatorHints struct {
	// RotationURL is where the operator should go to rotate this secret
	RotationURL string `json:"rotationUrl,omitempty"`
	// Documentation links for this secret
	DocURL string `json:"docUrl,omitempty"`
	// Free-form notes for operators
	Notes string `json:"notes,omitempty"`
	// Contact info for questions about this secret
	Contact string `json:"contact,omitempty"`
	// Provider is the service that manages this secret (e.g., "stripe", "aws")
	Provider string `json:"provider,omitempty"`
	// GSM reference for extended hints stored in GSM (optional)
	GSM *GSMRef `json:"gsm,omitempty"`
	// Format of GSM-stored hints (e.g., "json", "markdown")
	Format string `json:"format,omitempty"`
}

// ComputedConfig describes how to compute a key from other values.
type ComputedConfig struct {
	Kind      string            `json:"kind"` // "template"
	Template  string            `json:"template"`
	Inputs    []InputRef        `json:"inputs,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	ParamsRef *GSMRef           `json:"paramsRef,omitempty"`
}

// InputRef references a value from another key.
type InputRef struct {
	Var string `json:"var"` // Template variable name
	Ref KeyRef `json:"ref"`
}

// KeyRef references a specific key.
type KeyRef struct {
	ShortName string `json:"shortName,omitempty"` // Default: current secret
	KeyName   string `json:"keyName"`
}

// ParseMetadata parses metadata from YAML bytes with strict validation.
func ParseMetadata(data []byte) (*SecretMetadata, error) {
	var m SecretMetadata
	if err := yaml.UnmarshalStrict(data, &m); err != nil {
		return nil, WrapValidation("metadata", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
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
	validModes := map[string]bool{"generated": true, "external": true, "manual": true, "unknown": true}
	if !validModes[r.Mode] {
		return NewValidationError("rotation.mode", "must be 'generated', 'external', 'manual', or 'unknown'")
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
	if e.Source != "" {
		validSources := map[string]bool{"vendor": true, "certificate": true, "policy": true, "unknown": true}
		if !validSources[e.Source] {
			return NewValidationError("expiry.source", "must be 'vendor', 'certificate', 'policy', or 'unknown'")
		}
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

// GetVersion returns the GSM version as an integer.
func (g *GSMRef) GetVersion() (int, error) {
	return strconv.Atoi(g.Version)
}
