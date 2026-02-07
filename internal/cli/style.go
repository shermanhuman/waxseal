// Package cli provides the Cobra command structure for waxseal.
//
// This file defines the output style system for consistent terminal output.
// All CLI files should use these helpers instead of raw ANSI codes or fmt.Scanln.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
)

// ANSI escape sequences, gated on NO_COLOR.
// See https://no-color.org/
var (
	styleRed   = "\033[31m"
	styleGreen = "\033[32m"
	styleBold  = "\033[1m"
	styleDim   = "\033[2m"
	styleReset = "\033[0m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		styleRed = ""
		styleGreen = ""
		styleBold = ""
		styleDim = ""
		styleReset = ""
	}
}

// ── Semantic output helpers ─────────────────────────────────────────────────

// printSuccess prints a green check mark followed by a message.
//
//	✓ Resealed 4 keys
func printSuccess(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s✓%s %s\n", styleGreen, styleReset, msg)
}

// printWarning prints a warning symbol followed by a message to stderr.
//
//	⚠ Certificate expires in 7 days
func printWarning(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "%s⚠%s %s\n", styleRed, styleReset, msg)
}

// printError prints a red cross followed by a message to stderr.
//
//	✗ Failed to reseal my-app-secrets
func printError(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "%s✗%s %s\n", styleRed, styleReset, msg)
}

// printStep prints a bold step label (used in setup wizard steps).
//
//	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//	Step 1/7: GCP Project Setup
//	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
func printStep(step, total int, title string) {
	divider := strings.Repeat("━", 64)
	fmt.Println(divider)
	fmt.Printf("Step %d/%d: %s\n", step, total, title)
	fmt.Println(divider)
}

// printDim prints dimmed secondary information.
func printDim(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s%s%s\n", styleDim, msg, styleReset)
}

// ── Text helpers ────────────────────────────────────────────────────────────

// truncateStr truncates s to maxLen, appending "..." if shortened.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ── Confirmation helper ─────────────────────────────────────────────────────

// confirm prompts the user with a huh Confirm widget.
// Returns true if the user confirms, false otherwise.
// When the global --yes flag is set, returns true without prompting.
func confirm(title string) (bool, error) {
	if yes {
		return true, nil
	}
	var result bool
	err := huh.NewConfirm().
		Title(title).
		Value(&result).
		Run()
	return result, err
}

// ── Secret input helper ─────────────────────────────────────────────────────

// promptSecret prompts for a secret value using huh EchoModePassword.
// The value is never echoed to the terminal and never enters shell history.
func promptSecret(title string) (string, error) {
	var value string
	err := huh.NewInput().
		Title(title).
		EchoMode(huh.EchoModePassword).
		Value(&value).
		Run()
	return value, err
}

// ── Spinner helper ──────────────────────────────────────────────────────────

// withSpinner runs an action with a braille-style spinner.
// The spinner uses the default Dots type (braille ⣾ pattern).
//
//	var result []byte
//	err := withSpinner("Fetching certificate...", func() error {
//	    var e error
//	    result, e = fetchCert(ctx)
//	    return e
//	})
func withSpinner(title string, action func() error) error {
	var actionErr error
	err := spinner.New().
		Title(title).
		Type(spinner.Dots).
		Action(func() {
			actionErr = action()
		}).
		Run()
	if err != nil {
		return err
	}
	return actionErr
}
