package ui

import (
	"fmt"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
)

// Spec describes one input: the flag or argument that supplies it, and the
// prompt shown when it is missing on a terminal.
type Spec struct {
	Flag  string // "--rotation", "<secret>"
	Title string
	Help  string
}

// Prompter asks the user for a value. The huh-backed implementation draws on
// the terminal; noPrompter fails with a MissingInputError; ScriptedPrompter
// answers from a script in tests.
type Prompter interface {
	Input(s Spec, def string, validate func(string) error) (string, error)
	Secret(s Spec) ([]byte, error)
	Select(s Spec, choices []core.Choice, def string, allowOther bool) (string, error)
	Confirm(title string, def bool) (bool, error)
}

// noPrompter is used when the run is not interactive: every question is a
// missing input naming the flag that answers it.
type noPrompter struct{}

func (noPrompter) missing(s Spec) error {
	return &core.MissingInputError{Field: s.Flag}
}
func (n noPrompter) Input(s Spec, _ string, _ func(string) error) (string, error) {
	return "", n.missing(s)
}
func (n noPrompter) Secret(s Spec) ([]byte, error) { return nil, n.missing(s) }
func (n noPrompter) Select(s Spec, choices []core.Choice, _ string, _ bool) (string, error) {
	return "", n.missing(Spec{Flag: s.Flag + " (" + strings.Join(values(choices), "|") + ")"})
}
func (noPrompter) Confirm(title string, _ bool) (bool, error) {
	return false, &ConfirmRequiredError{Action: title}
}

// ScriptedPrompter answers prompts from a queue, for tests. An unexpected
// prompt, or running out of answers, is a test failure surfaced as an error.
type ScriptedPrompter struct {
	Answers []string
	Asked   []Spec
}

func (p *ScriptedPrompter) next(s Spec) (string, error) {
	p.Asked = append(p.Asked, s)
	if len(p.Answers) == 0 {
		return "", fmt.Errorf("scripted prompter: unexpected prompt for %s", s.Flag)
	}
	a := p.Answers[0]
	p.Answers = p.Answers[1:]
	return a, nil
}
func (p *ScriptedPrompter) Input(s Spec, _ string, validate func(string) error) (string, error) {
	v, err := p.next(s)
	if err != nil {
		return "", err
	}
	if validate != nil {
		if err := validate(v); err != nil {
			return "", err
		}
	}
	return v, nil
}
func (p *ScriptedPrompter) Secret(s Spec) ([]byte, error) {
	v, err := p.next(s)
	return []byte(v), err
}
func (p *ScriptedPrompter) Select(s Spec, choices []core.Choice, _ string, allowOther bool) (string, error) {
	v, err := p.next(s)
	if err != nil {
		return "", err
	}
	if !allowOther && !contains(values(choices), v) {
		return "", fmt.Errorf("scripted prompter: %q is not a choice for %s", v, s.Flag)
	}
	return v, nil
}
func (p *ScriptedPrompter) Confirm(title string, _ bool) (bool, error) {
	v, err := p.next(Spec{Flag: "confirm", Title: title})
	if err != nil {
		return false, err
	}
	return v == "y" || v == "yes", nil
}

func values(choices []core.Choice) []string {
	out := make([]string, len(choices))
	for i, c := range choices {
		out[i] = c.Value
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
