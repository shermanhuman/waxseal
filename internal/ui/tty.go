// Package ui is the only code that talks to the terminal: prompts, output,
// colour, spinners. Commands resolve every input through Inputs so that a
// value comes from a flag when given, from a prompt only on a TTY, and
// otherwise from a clear error naming the flag.
package ui

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// IsTerminal reports whether w is a terminal. Anything that is not an
// *os.File (a buffer in tests, a pipe wrapper) is not.
func IsTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Interactive decides whether prompting is allowed: not --no-input, not in
// CI, and both stdin and stderr are terminals. stderr rather than stdout
// because prompts are drawn there, so `waxseal ... -o json | jq` can still
// ask a question.
func Interactive(noInput bool, getenv func(string) string, stdin, stderr any) bool {
	if noInput || truthy(getenv("CI")) {
		return false
	}
	return IsTerminal(stdin) && IsTerminal(stderr)
}

// ColorEnabled decides whether to colour output written to w.
func ColorEnabled(noColor bool, getenv func(string) string, w any) bool {
	if noColor || getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	return IsTerminal(w)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no":
		return false
	}
	return true
}
