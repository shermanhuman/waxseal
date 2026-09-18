package ui

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Result is what a command produces. JSON output encodes the value itself;
// text output calls Text.
type Result interface {
	Text(p *Printer)
}

// Printer writes a command's output. Data goes to Out (stdout); progress,
// warnings, errors and hints go to Err (stderr), so piping stdout gives
// clean data and the terminal still shows what happened.
type Printer struct {
	Out, Err io.Writer
	outColor bool
	errColor bool
	errTTY   bool
}

// NewPrinter binds a printer to two writers. outColor/errColor enable ANSI
// colour per stream; errTTY enables the spinner.
func NewPrinter(out, err io.Writer, outColor, errColor, errTTY bool) *Printer {
	return &Printer{Out: out, Err: err, outColor: outColor, errColor: errColor, errTTY: errTTY}
}

const (
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiReset  = "\033[0m"
)

func paint(enabled bool, code, s string) string {
	if !enabled {
		return s
	}
	return code + s + ansiReset
}

// Printf writes data to stdout.
func (p *Printer) Printf(format string, a ...any) { fmt.Fprintf(p.Out, format, a...) }

// Println writes a data line to stdout.
func (p *Printer) Println(a ...any) { fmt.Fprintln(p.Out, a...) }

// Success reports a completed step on stderr.
func (p *Printer) Success(format string, a ...any) {
	fmt.Fprintf(p.Err, "%s %s\n", paint(p.errColor, ansiGreen, "✓"), fmt.Sprintf(format, a...))
}

// Warn reports a warning on stderr.
func (p *Printer) Warn(format string, a ...any) {
	fmt.Fprintf(p.Err, "%s %s\n", paint(p.errColor, ansiYellow, "!"), fmt.Sprintf(format, a...))
}

// Error reports a failure on stderr.
func (p *Printer) Error(format string, a ...any) {
	fmt.Fprintf(p.Err, "%s %s\n", paint(p.errColor, ansiRed, "✗"), fmt.Sprintf(format, a...))
}

// Info writes a plain line to stderr.
func (p *Printer) Info(format string, a ...any) {
	fmt.Fprintf(p.Err, "%s\n", fmt.Sprintf(format, a...))
}

// Dim writes a de-emphasised line to stderr.
func (p *Printer) Dim(format string, a ...any) {
	fmt.Fprintln(p.Err, paint(p.errColor, ansiDim, fmt.Sprintf(format, a...)))
}

// Next lists follow-up actions on stderr.
func (p *Printer) Next(steps []string) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(p.Err)
	fmt.Fprintln(p.Err, paint(p.errColor, ansiBold, "Next:"))
	for _, s := range steps {
		fmt.Fprintf(p.Err, "  %s\n", s)
	}
}

// Table writes aligned columns to stdout. Empty cells render as "-".
func (p *Printer) Table(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i := range headers {
			if i < len(row) {
				widths[i] = max(widths[i], utf8.RuneCountInString(cell(row, i)))
			}
		}
	}
	line := func(cells func(int) string, bold bool) {
		var b strings.Builder
		for i := range headers {
			c := cells(i)
			if i < len(headers)-1 {
				c += strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2)
			}
			b.WriteString(c)
		}
		fmt.Fprintln(p.Out, paint(p.outColor && bold, ansiBold, strings.TrimRight(b.String(), " ")))
	}
	line(func(i int) string { return headers[i] }, true)
	for _, row := range rows {
		line(func(i int) string { return cell(row, i) }, false)
	}
}

func cell(row []string, i int) string {
	if i >= len(row) || row[i] == "" {
		return "-"
	}
	return row[i]
}

// KV writes aligned key/value pairs to stdout.
func (p *Printer) KV(pairs [][2]string) {
	width := 0
	for _, kv := range pairs {
		width = max(width, utf8.RuneCountInString(kv[0]))
	}
	for _, kv := range pairs {
		fmt.Fprintf(p.Out, "%-*s  %s\n", width+1, kv[0]+":", kv[1])
	}
}
