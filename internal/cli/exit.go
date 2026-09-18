package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/proc"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// Exit codes.
const (
	ExitOK        = 0
	ExitFailure   = 1   // runtime failure, check errors, partial reseal
	ExitUsage     = 2   // bad flags or args, missing input, validation, warnings with --fail-on-warning
	ExitCancelled = 130 // SIGINT or a declined prompt
)

// ExitError carries an exit code for a result that already told its story
// (a failed check, a partial reseal). Nothing more is printed.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string { return fmt.Sprintf("exit %d", e.Code) }

// usageError marks cobra flag and argument errors.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// Main runs the CLI and returns the process exit code. It is the only place
// exit codes are decided.
func Main(ctx context.Context, app *App, args []string) int {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd(app)
	root.SetArgs(args)
	root.SetIn(app.Stdin)
	root.SetOut(app.Stdout)
	root.SetErr(app.Stderr)
	err := root.ExecuteContext(ctx)
	app.Close()
	return report(app.Stderr, err)
}

// report prints err the way the user should see it and returns the code.
func report(stderr io.Writer, err error) int {
	if err == nil {
		return ExitOK
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	if errors.Is(err, ui.ErrCancelled) || errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "Cancelled.")
		return ExitCancelled
	}
	fmt.Fprintf(stderr, "Error: %s\n", err)
	if hint := hintFor(err); hint != "" {
		fmt.Fprintf(stderr, "  hint: %s\n", hint)
	}
	return codeFor(err)
}

func codeFor(err error) int {
	var (
		usage   *usageError
		missing *core.MissingInputError
		confirm *ui.ConfirmRequiredError
	)
	switch {
	case errors.As(err, &usage), errors.As(err, &missing), errors.As(err, &confirm), errors.Is(err, core.ErrValidation):
		return ExitUsage
	case strings.HasPrefix(err.Error(), "unknown command"):
		// cobra reports an unknown subcommand as a plain error with no hook.
		return ExitUsage
	}
	return ExitFailure
}

// hintFor is the one table of remediation hints.
func hintFor(err error) string {
	var hint *ui.HintError
	if errors.As(err, &hint) {
		return hint.Hint
	}
	var missing *core.MissingInputError
	switch {
	case errors.As(err, &missing):
		return "pass " + missing.Field + ", or run on a terminal to be prompted"
	case errors.Is(err, ops.ErrNotRegistered):
		return "see `waxseal secret list`; register a manifest with `waxseal import`"
	case errors.Is(err, core.ErrRetired):
		return "retired secrets are read-only; see `waxseal secret show`"
	case errors.Is(err, core.ErrUnauthenticated):
		return "run `gcloud auth application-default login`"
	case errors.Is(err, proc.ErrNotInstalled):
		return "install the missing tool and make sure it is on PATH"
	}
	return ""
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// flagErrorFunc turns cobra's flag errors into usage errors without cobra
// printing usage text itself.
func flagErrorFunc(_ *cobra.Command, err error) error {
	return &usageError{err: err}
}

// argsUsage wraps a cobra positional-args validator so its errors exit 2.
func argsUsage(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return &usageError{err: err}
		}
		return nil
	}
}
