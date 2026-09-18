// Package proc runs external programs. Every subprocess waxseal starts goes
// through Run, so tests can swap in a Runner that asserts arguments and
// returns canned output.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner has the signature of Run. Port packages hold one and default it to
// Run, so a test can inject a fake.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// ErrNotInstalled is wrapped when the program is not on PATH.
var ErrNotInstalled = errors.New("not installed")

// ExitError is returned when the program ran but exited non-zero.
type ExitError struct {
	Name   string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("%s exited with code %d", e.Name, e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Name, msg)
}

// LookPath reports whether name is on PATH, wrapping ErrNotInstalled if not.
func LookPath(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	return nil
}

// Run executes name with args, feeding stdin, and returns stdout. A non-zero
// exit becomes an *ExitError carrying stderr; a missing program wraps
// ErrNotInstalled.
func Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if err := LookPath(name); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", name, ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &ExitError{Name: name, Code: exitErr.ExitCode(), Stderr: stderr.String()}
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}
