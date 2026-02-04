// Package template provides the computed key template engine.
// This file adds Payload type for single GSM JSON storage of templated secrets.
package template

import (
	"encoding/json"
	"fmt"
)

// Payload represents the JSON structure stored in GSM for templated secrets.
// Uses {{secret}} as the standard rotatable variable.
type Payload struct {
	SchemaVersion int               `json:"schemaVersion"`
	Type          string            `json:"type"` // always "templated"
	Template      string            `json:"template"`
	Values        map[string]string `json:"values"`
	Secret        string            `json:"secret"`
	Generator     *GeneratorConfig  `json:"generator,omitempty"`
	Computed      string            `json:"computed"`
}

// GeneratorConfig specifies how to generate the {{secret}} value.
type GeneratorConfig struct {
	Kind  string `json:"kind"`  // randomBase64 | randomHex
	Bytes int    `json:"bytes"` // default 32
}

// NewPayload creates a new templated payload with defaults.
func NewPayload(templateStr string, values map[string]string, secret string, gen *GeneratorConfig) (*Payload, error) {
	p := &Payload{
		SchemaVersion: 1,
		Type:          "templated",
		Template:      templateStr,
		Values:        values,
		Secret:        secret,
		Generator:     gen,
	}

	computed, err := p.Compute()
	if err != nil {
		return nil, err
	}
	p.Computed = computed
	return p, nil
}

// ParsePayload parses a JSON payload from bytes.
func ParsePayload(data []byte) (*Payload, error) {
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse template payload: %w", err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported schema version: %d", p.SchemaVersion)
	}
	if p.Type != "templated" {
		return nil, fmt.Errorf("unexpected payload type: %s", p.Type)
	}
	return &p, nil
}

// Marshal serializes the payload to JSON.
func (p *Payload) Marshal() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// Compute generates the computed value from template + values + secret.
// Uses the existing Template engine.
func (p *Payload) Compute() (string, error) {
	tmpl, err := Parse(p.Template)
	if err != nil {
		return "", err
	}

	// Build the full values map with secret included
	allValues := make(map[string]string, len(p.Values)+1)
	for k, v := range p.Values {
		allValues[k] = v
	}
	allValues["secret"] = p.Secret

	return tmpl.Execute(allValues)
}

// Validate checks that the payload is valid.
func (p *Payload) Validate() error {
	if err := ValidateSyntax(p.Template); err != nil {
		return err
	}

	tmpl, err := Parse(p.Template)
	if err != nil {
		return err
	}

	// Check that all required variables (except secret) have values
	vars := tmpl.Variables()
	hasSecret := false
	for _, v := range vars {
		if v == "secret" {
			hasSecret = true
			continue
		}
		if _, ok := p.Values[v]; !ok {
			return fmt.Errorf("missing value for template variable {{%s}}", v)
		}
	}

	if p.Generator != nil && !hasSecret {
		return fmt.Errorf("template with generator must include {{secret}} variable")
	}

	return nil
}

// UpdateSecret sets a new secret value and recomputes the output.
func (p *Payload) UpdateSecret(newSecret string) error {
	p.Secret = newSecret
	computed, err := p.Compute()
	if err != nil {
		return err
	}
	p.Computed = computed
	return nil
}
