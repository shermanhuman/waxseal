package ui

import (
	"context"
	"fmt"

	"github.com/charmbracelet/huh/spinner"
)

// Spin runs fn while showing title. On a terminal it animates a spinner on
// stderr; otherwise it prints the title and each progress update as plain
// lines, which reads well in CI logs. fn's progress updates are ignored
// while the spinner animates.
func (p *Printer) Spin(ctx context.Context, title string, fn func(progress func(string)) error) error {
	if !p.errTTY {
		p.Dim("%s...", title)
		return fn(func(msg string) { p.Dim("  %s", msg) })
	}
	var fnErr error
	err := spinner.New().
		Title(title + "...").
		Type(spinner.Dots).
		Output(p.Err).
		Context(ctx).
		Action(func() { fnErr = fn(func(string) {}) }).
		Run()
	if err != nil {
		return fmt.Errorf("%s: %w", title, err)
	}
	return fnErr
}
