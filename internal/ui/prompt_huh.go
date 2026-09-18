package ui

import (
	"context"
	"errors"
	"io"

	"github.com/charmbracelet/huh"

	"github.com/shermanhuman/waxseal/internal/core"
)

// huhPrompter draws prompts with charmbracelet/huh on stderr.
type huhPrompter struct {
	ctx        context.Context
	in         io.Reader
	out        io.Writer
	accessible bool
}

// NewPrompter returns a terminal prompter reading from in and drawing on out
// (normally stderr). accessible selects huh's screen-reader mode.
func NewPrompter(ctx context.Context, in io.Reader, out io.Writer, accessible bool) Prompter {
	return &huhPrompter{ctx: ctx, in: in, out: out, accessible: accessible}
}

func (p *huhPrompter) run(field huh.Field) error {
	form := huh.NewForm(huh.NewGroup(field)).
		WithInput(p.in).
		WithOutput(p.out).
		WithAccessible(p.accessible).
		WithShowHelp(false)
	err := form.RunWithContext(p.ctx)
	if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, context.Canceled) {
		return ErrCancelled
	}
	return err
}

func (p *huhPrompter) Input(s Spec, def string, validate func(string) error) (string, error) {
	value := def
	field := huh.NewInput().Title(s.Title).Description(s.Help).Value(&value)
	if validate != nil {
		field = field.Validate(validate)
	}
	if err := p.run(field); err != nil {
		return "", err
	}
	return value, nil
}

func (p *huhPrompter) Secret(s Spec) ([]byte, error) {
	var value string
	field := huh.NewInput().Title(s.Title).Description(s.Help).EchoMode(huh.EchoModePassword).Value(&value).
		Validate(func(v string) error {
			if v == "" {
				return errors.New("a value is required")
			}
			return nil
		})
	if err := p.run(field); err != nil {
		return nil, err
	}
	return []byte(value), nil
}

const other = "\x00other"

func (p *huhPrompter) Select(s Spec, choices []core.Choice, def string, allowOther bool) (string, error) {
	options := make([]huh.Option[string], 0, len(choices)+1)
	for _, c := range choices {
		label := c.Label
		if c.Help != "" {
			label += "  (" + c.Help + ")"
		}
		options = append(options, huh.NewOption(label, c.Value))
	}
	if allowOther {
		options = append(options, huh.NewOption("Enter manually...", other))
	}
	value := def
	field := huh.NewSelect[string]().Title(s.Title).Description(s.Help).Options(options...).Value(&value).
		Filtering(len(options) > 8)
	if err := p.run(field); err != nil {
		return "", err
	}
	if value == other {
		return p.Input(s, "", func(v string) error {
			if v == "" {
				return errors.New("a value is required")
			}
			return nil
		})
	}
	return value, nil
}

func (p *huhPrompter) Confirm(title string, def bool) (bool, error) {
	value := def
	if err := p.run(huh.NewConfirm().Title(title).Value(&value)); err != nil {
		return false, err
	}
	return value, nil
}
