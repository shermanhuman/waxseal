package core

import (
	"fmt"
	"slices"
	"strings"
)

// Rotation modes.
const (
	RotationGenerated = "generated"
	RotationExternal  = "external"
	RotationStatic    = "static"
	RotationUnknown   = "unknown"
)

// Generator kinds.
const (
	GeneratorRandomBase64 = "randomBase64"
	GeneratorRandomHex    = "randomHex"
	GeneratorRandomBytes  = "randomBytes"
)

// SealedSecret scopes.
const (
	ScopeStrict        = "strict"
	ScopeNamespaceWide = "namespace-wide"
	ScopeClusterWide   = "cluster-wide"
)

// Choice is one allowed value of an Enum, with the text a prompt shows for it.
type Choice struct {
	Value string
	Label string
	Help  string
}

// Enum is a closed vocabulary defined once. Validation, flag help, shell
// completion and prompt options all read from the same table, so they cannot
// drift apart.
type Enum struct {
	Name    string
	Choices []Choice
	// Open enums suggest Choices but accept any non-empty value.
	Open bool
}

// Values returns the allowed values in display order.
func (e Enum) Values() []string {
	values := make([]string, len(e.Choices))
	for i, c := range e.Choices {
		values[i] = c.Value
	}
	return values
}

// Has reports whether v is an allowed value.
func (e Enum) Has(v string) bool {
	if e.Open {
		return v != ""
	}
	return slices.Contains(e.Values(), v)
}

// Validate returns a validation error for field when v is not allowed.
func (e Enum) Validate(field, v string) error {
	if e.Has(v) {
		return nil
	}
	return NewValidationError(field, fmt.Sprintf("invalid %s %q (valid: %s)", e.Name, v, strings.Join(e.Values(), ", ")))
}

// Only returns the enum restricted to the given values, keeping table order.
func (e Enum) Only(values ...string) Enum {
	out := Enum{Name: e.Name, Open: e.Open}
	for _, c := range e.Choices {
		if slices.Contains(values, c.Value) {
			out.Choices = append(out.Choices, c)
		}
	}
	return out
}

// The vocabularies.
var (
	RotationModes = Enum{Name: "rotation mode", Choices: []Choice{
		{RotationGenerated, "Generated", "waxseal generates a new value on `rotate`"},
		{RotationExternal, "External", "rotated at a vendor; supply the new value with `key set`"},
		{RotationStatic, "Static", "not expected to change"},
		{RotationUnknown, "Unknown", "decide later"},
	}}

	// GeneratorKinds lists every kind valid in metadata. The CLI offers
	// OfferedGeneratorKinds: raw bytes cannot be pasted or inspected.
	GeneratorKinds = Enum{Name: "generator kind", Choices: []Choice{
		{GeneratorRandomBase64, "Base64", "base64-encoded random bytes"},
		{GeneratorRandomHex, "Hex", "hex-encoded random bytes"},
		{GeneratorRandomBytes, "Raw bytes", "raw random bytes"},
	}}
	OfferedGeneratorKinds = GeneratorKinds.Only(GeneratorRandomBase64, GeneratorRandomHex)

	Scopes = Enum{Name: "scope", Choices: []Choice{
		{ScopeStrict, "Strict", "bound to this name and namespace"},
		{ScopeNamespaceWide, "Namespace-wide", "can be renamed within the namespace"},
		{ScopeClusterWide, "Cluster-wide", "can be moved to any namespace"},
	}}

	SecretTypes = Enum{Name: "secret type", Open: true, Choices: []Choice{
		{"Opaque", "Opaque", "arbitrary key/value pairs"},
		{"kubernetes.io/dockerconfigjson", "Docker config", "image pull credentials"},
		{"kubernetes.io/tls", "TLS", "certificate and private key"},
		{"kubernetes.io/basic-auth", "Basic auth", "username and password"},
		{"kubernetes.io/ssh-auth", "SSH auth", "SSH private key"},
	}}
)
