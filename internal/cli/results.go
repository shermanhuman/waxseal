package cli

import (
	"fmt"

	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

func errInvalidOutput(o string) error {
	return fmt.Errorf("invalid output format %q (valid: text, json)", o)
}

// mutationResult is the shared result of every command that changes
// something. The Changes list renders the same way for a dry run and a
// real run; only the verb differs.
type mutationResult struct {
	Summary string       `json:"summary"`
	DryRun  bool         `json:"dryRun"`
	Changes []ops.Change `json:"changes"`
	Next    []string     `json:"next,omitempty"`
}

func (r *mutationResult) Text(p *ui.Printer) {
	verb := map[string]string{"create": "Created", "update": "Updated", "delete": "Deleted"}
	if r.DryRun {
		verb = map[string]string{"create": "Would create", "update": "Would update", "delete": "Would delete"}
	}
	for _, c := range r.Changes {
		p.Printf("%s %s %s\n", verb[c.Op], c.Kind, c.Target)
	}
	if r.Summary != "" {
		p.Println(r.Summary)
	}
	if !r.DryRun {
		p.Next(r.Next)
	}
}
