// Package template provides the computed key template engine.
package template

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Template represents a parsed template with variables.
type Template struct {
	raw       string
	variables []string
}

// variablePattern matches {{variable}} syntax.
var variablePattern = regexp.MustCompile(`\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}`)

// Parse parses a template string and extracts variable names.
func Parse(template string) (*Template, error) {
	if template == "" {
		return nil, core.NewValidationError("template", "cannot be empty")
	}

	matches := variablePattern.FindAllStringSubmatch(template, -1)
	seen := make(map[string]bool)
	var variables []string

	for _, match := range matches {
		varName := match[1]
		if !seen[varName] {
			seen[varName] = true
			variables = append(variables, varName)
		}
	}

	return &Template{
		raw:       template,
		variables: variables,
	}, nil
}

// Variables returns the list of variable names in the template.
func (t *Template) Variables() []string {
	result := make([]string, len(t.variables))
	copy(result, t.variables)
	return result
}

// Raw returns the original template string.
func (t *Template) Raw() string {
	return t.raw
}

// Execute renders the template with the provided values.
// Returns an error if any required variable is missing.
func (t *Template) Execute(values map[string]string) (string, error) {
	// Check for missing variables
	var missing []string
	for _, v := range t.variables {
		if _, ok := values[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return "", core.NewValidationError("template", fmt.Sprintf("missing variables: %s", strings.Join(missing, ", ")))
	}

	// Replace all variables
	result := t.raw
	for name, value := range values {
		placeholder := "{{" + name + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result, nil
}

// ValidateSyntax checks if a template string has valid syntax.
// Returns an error if the template contains malformed placeholders.
func ValidateSyntax(template string) error {
	// Check for unmatched braces
	openCount := strings.Count(template, "{{")
	closeCount := strings.Count(template, "}}")

	if openCount != closeCount {
		return core.NewValidationError("template", "unmatched braces")
	}

	// Check for empty placeholders
	if strings.Contains(template, "{{}}") {
		return core.NewValidationError("template", "empty placeholder")
	}

	// Check for nested braces
	if strings.Contains(template, "{{{") || strings.Contains(template, "}}}") {
		return core.NewValidationError("template", "nested braces not allowed")
	}

	return nil
}
