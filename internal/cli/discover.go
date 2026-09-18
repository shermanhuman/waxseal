package cli

import (
	"context"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

type discoverResult struct {
	Manifests []ops.Discovered `json:"manifests"`
}

func (r *discoverResult) Text(p *ui.Printer) {
	if len(r.Manifests) == 0 {
		p.Info("No SealedSecret manifests found.")
		return
	}
	rows := make([][]string, 0, len(r.Manifests))
	unregistered := 0
	for _, d := range r.Manifests {
		status := d.Registered
		if status == "" {
			status = "(new)"
			unregistered++
		}
		rows = append(rows, []string{d.Path, d.Namespace + "/" + d.Name, d.Scope, strconv.Itoa(len(d.Keys)), status})
	}
	p.Table([]string{"MANIFEST", "SEALEDSECRET", "SCOPE", "KEYS", "REGISTERED AS"}, rows)
	if unregistered > 0 {
		var names []string
		for _, d := range r.Manifests {
			if d.Registered == "" {
				names = append(names, d.Suggested)
			}
		}
		p.Next([]string{"register them from the cluster: waxseal import " + strings.Join(names, " ")})
	}
}

func newDiscoverCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Find SealedSecret manifests in the repository",
		Long: `Walk the repository for SealedSecret manifests and report which ones
metadata already covers. Nothing is written; register new manifests with
` + "`waxseal import`" + `, which reads their plaintext from the cluster.`,
		GroupID: groupSetup,
		Args:    argsUsage(cobra.NoArgs),
		RunE: app.run(Needs{}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
			svc, err := app.Service(ctx, Needs{}, false)
			if err != nil {
				return nil, err
			}
			found, err := svc.Discover()
			if err != nil {
				return nil, err
			}
			return &discoverResult{Manifests: found}, nil
		}),
	}
}
