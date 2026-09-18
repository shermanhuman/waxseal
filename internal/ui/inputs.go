package ui

import "github.com/shermanhuman/waxseal/internal/core"

// Inputs resolves each input the same way: a flag or argument that was set
// wins; otherwise, on a terminal, the Prompter is asked (offering the
// default); otherwise the default is used, and an input with no default
// fails naming the flag. --yes answers confirmations and nothing else.
type Inputs struct {
	Prompter    Prompter
	Yes         bool
	Interactive bool
}

// NewInputs picks the prompter for the run: p when interactive, otherwise
// one that turns every question into a missing-input error.
func NewInputs(interactive, yes bool, p Prompter) *Inputs {
	if !interactive || p == nil {
		p = noPrompter{}
	}
	return &Inputs{Prompter: p, Yes: yes, Interactive: interactive}
}

// String resolves a free-text input.
func (in *Inputs) String(s Spec, set bool, val, def string, validate func(string) error) (string, error) {
	if set {
		if validate != nil {
			if err := validate(val); err != nil {
				return "", core.NewValidationError(s.Flag, err.Error())
			}
		}
		return val, nil
	}
	if def != "" && !in.Interactive {
		return def, nil
	}
	return in.Prompter.Input(s, def, validate)
}

// Choice resolves an input drawn from an Enum. A flag value is validated
// against it; a prompt offers its choices, plus "enter manually" for open
// enums.
func (in *Inputs) Choice(s Spec, set bool, val string, e core.Enum, def string) (string, error) {
	if set {
		if err := e.Validate(s.Flag, val); err != nil {
			return "", err
		}
		return val, nil
	}
	if def != "" && !in.Interactive {
		return def, nil
	}
	return in.Prompter.Select(s, e.Choices, def, e.Open)
}

// Secret asks for a secret value with masked input. Secrets never come from
// flags, so there is nothing to resolve from; callers handle --from-file and
// --generate before calling this.
func (in *Inputs) Secret(s Spec) ([]byte, error) {
	return in.Prompter.Secret(s)
}

// Confirm gates an action. --yes accepts; interactive asks; otherwise a
// ConfirmRequiredError. Declining is ErrCancelled.
func (in *Inputs) Confirm(action string) error {
	if in.Yes {
		return nil
	}
	ok, err := in.Prompter.Confirm(action+"?", false)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCancelled
	}
	return nil
}

// Offer asks an optional yes/no question. It is only ever asked on a
// terminal; --yes does not turn optional steps on.
func (in *Inputs) Offer(question string) bool {
	if !in.Interactive {
		return false
	}
	ok, err := in.Prompter.Confirm(question, false)
	return err == nil && ok
}

// Arg returns the i-th positional argument and whether it was given.
func Arg(args []string, i int) (string, bool) {
	if i < len(args) {
		return args[i], true
	}
	return "", false
}
