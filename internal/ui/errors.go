package ui

import "errors"

// ErrCancelled is returned when the user aborts a prompt or declines a
// confirmation. The CLI exits 130 quietly, without "Error:".
var ErrCancelled = errors.New("cancelled")

// ConfirmRequiredError is returned when a confirmation is needed but the run
// is non-interactive and --yes was not given.
type ConfirmRequiredError struct {
	Action string
}

func (e *ConfirmRequiredError) Error() string {
	return "confirmation required to " + e.Action + "; pass --yes"
}

// HintError attaches a remediation hint to an error. The CLI prints the hint
// under the error message.
type HintError struct {
	Err  error
	Hint string
}

func (e *HintError) Error() string { return e.Err.Error() }
func (e *HintError) Unwrap() error { return e.Err }

// WithHint wraps err with a hint. A nil err stays nil.
func WithHint(err error, hint string) error {
	if err == nil {
		return nil
	}
	return &HintError{Err: err, Hint: hint}
}
