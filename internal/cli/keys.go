package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/core"
)

// KeySpec represents a parsed key specification from CLI flags.
// Supports formats:
//   - "name"                    → static key (prompts for value)
//   - "name:random"             → generated key with default generator
//   - "name:template=GK{{secret}}" → templated key with prefix
type KeySpec struct {
	Name         string
	Kind         string // "static", "random", "template"
	Template     string // Only for kind="template", e.g., "GK{{secret}}"
	RotationMode string // "static", "generated", "external"
}

// ParseKeySpec parses a --key flag value into a KeySpec.
// Examples:
//
//	"username"                  → KeySpec{Name: "username", Kind: "static"}
//	"password:random"           → KeySpec{Name: "password", Kind: "random"}
//	"access-key:template=GK{{secret}}" → KeySpec{Name: "access-key", Kind: "template", Template: "GK{{secret}}"}
func ParseKeySpec(spec string) (*KeySpec, error) {
	if spec == "" {
		return nil, fmt.Errorf("key spec cannot be empty")
	}

	// Split on first colon
	parts := strings.SplitN(spec, ":", 2)
	name := parts[0]

	if name == "" {
		return nil, fmt.Errorf("key name cannot be empty in %q", spec)
	}

	if len(parts) == 1 {
		// Just "name" — static key
		return &KeySpec{
			Name:         name,
			Kind:         "static",
			RotationMode: "static",
		}, nil
	}

	modifier := parts[1]

	// Check for "random"
	if modifier == "random" {
		return &KeySpec{
			Name:         name,
			Kind:         "random",
			RotationMode: "generated",
		}, nil
	}

	// Check for "template=..."
	if strings.HasPrefix(modifier, "template=") {
		template := strings.TrimPrefix(modifier, "template=")
		if template == "" {
			return nil, fmt.Errorf("template cannot be empty in %q", spec)
		}
		if !strings.Contains(template, "{{secret}}") {
			return nil, fmt.Errorf("template must contain {{secret}} placeholder in %q", spec)
		}
		return &KeySpec{
			Name:         name,
			Kind:         "template",
			Template:     template,
			RotationMode: "generated", // templated keys with {{secret}} are rotatable
		}, nil
	}

	return nil, fmt.Errorf("unknown modifier %q in key spec %q (use 'random' or 'template=...')", modifier, spec)
}

// PromptRotationMode shows an interactive prompt for selecting rotation mode.
// Returns one of: "static", "generated", "external".
func PromptRotationMode(keyName string) (string, error) {
	var mode string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Rotation mode for '%s'", keyName)).
		Description("How should this key be rotated?").
		Options(
			huh.NewOption("Static - not expected to rotate (waxseal rotate ignores)", "static"),
			huh.NewOption("Generated - waxseal auto-rotates", "generated"),
			huh.NewOption("External - managed externally (waxseal rotate prompts with hints)", "external"),
		).
		Value(&mode).
		Run()
	return mode, err
}

// PromptGeneratorKind shows an interactive prompt for selecting generator kind.
// Returns one of: "randomBase64", "randomHex".
func PromptGeneratorKind(keyName string) (string, error) {
	var kind string
	err := huh.NewSelect[string]().
		Title(fmt.Sprintf("Generator type for '%s'", keyName)).
		Description("How should the secret value be generated?").
		Options(
			huh.NewOption("Random Base64 (URL-safe, good for tokens/passwords)", "randomBase64"),
			huh.NewOption("Random Hex (hexadecimal, e.g. for Garage S3 keys)", "randomHex"),
		).
		Value(&kind).
		Run()
	return kind, err
}

// PromptSecretValue shows a secure password-style input for entering a secret value.
func PromptSecretValue(keyName string) (string, error) {
	var value string
	err := huh.NewInput().
		Title(fmt.Sprintf("Enter value for '%s'", keyName)).
		EchoMode(huh.EchoModePassword).
		Value(&value).
		Run()
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("value cannot be empty")
	}
	return value, nil
}

// GeneratorKinds returns valid generator kind values for validation.
func GeneratorKinds() []string {
	return []string{"randomBase64", "randomHex"}
}

// ValidateGeneratorKind checks if a generator kind is valid.
func ValidateGeneratorKind(kind string) error {
	for _, valid := range GeneratorKinds() {
		if kind == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid generator kind %q (valid: %s)", kind, strings.Join(GeneratorKinds(), ", "))
}

// BuildGeneratorConfig creates a GeneratorConfig with validation.
func BuildGeneratorConfig(kind string, bytes int) (*core.GeneratorConfig, error) {
	if err := ValidateGeneratorKind(kind); err != nil {
		return nil, err
	}
	if bytes <= 0 {
		bytes = 32 // default
	}
	return &core.GeneratorConfig{
		Kind:  kind,
		Bytes: bytes,
	}, nil
}
