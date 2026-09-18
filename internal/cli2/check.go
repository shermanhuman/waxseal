package cli2

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

type checkResult struct {
	Findings []ops.Finding `json:"findings"`
	Severity string        `json:"severity"`
}

func (r *checkResult) Text(p *ui.Printer) {
	for _, f := range r.Findings {
		line := f.Message
		if f.Subject != "" {
			line = f.Subject + ": " + line
		}
		line = f.Check + "  " + line
		switch f.Severity {
		case ops.SeverityError:
			p.Error("%s", line)
		case ops.SeverityWarning:
			p.Warn("%s", line)
		default:
			p.Success("%s", line)
		}
	}
}

func newCheckCmd(app *App) *cobra.Command {
	var warnDays int
	var failOnWarning bool
	cmd := &cobra.Command{
		Use:   "check [" + joinValues(ops.Checks) + "]...",
		Short: "Check certificate, expiry, metadata, GSM and cluster state",
		Long: `Run health checks. With no arguments every check runs, and the ones that
need GSM credentials or cluster access are skipped when those are absent.
Naming a check makes it mandatory.

Exit codes: 0 healthy, 1 errors found, 2 warnings found with --fail-on-warning.`,
		GroupID:   groupOps,
		ValidArgs: ops.Checks.Values(),
		Args:      argsUsage(cobra.OnlyValidArgs),
		RunE: app.run(Needs{Config: true}, func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
			needs := Needs{}
			for _, name := range args {
				switch name {
				case ops.CheckGSM:
					needs.GSM = true
				case ops.CheckCluster:
					needs.Kubectl = true
				}
			}
			optional := len(args) == 0
			if optional {
				needs = Needs{GSM: app.gsmLikelyAvailable(ctx), Kubectl: app.LookPath("kubectl") == nil}
			} else if err := app.preflight(ctx, io, needs); err != nil {
				return nil, err
			}
			svc, err := app.Service(ctx, needs, optional)
			if err != nil {
				return nil, err
			}

			var findings []ops.Finding
			err = io.P.Spin(ctx, "Checking", func(progress func(string)) error {
				var err error
				findings, err = svc.Check(ctx, ops.CheckInput{Checks: args, WarnDays: warnDays, Progress: progress})
				return err
			})
			if err != nil {
				return nil, err
			}
			r := &checkResult{Findings: findings, Severity: ops.MaxSeverity(findings)}
			switch {
			case r.Severity == ops.SeverityError:
				return r, &ExitError{Code: ExitFailure}
			case r.Severity == ops.SeverityWarning && failOnWarning:
				return r, &ExitError{Code: ExitUsage}
			}
			return r, nil
		}),
	}
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "warn when a certificate or key expires within this many days")
	cmd.Flags().BoolVar(&failOnWarning, "fail-on-warning", false, "exit 2 when there are warnings")
	return cmd
}

// gsmLikelyAvailable is the cheap test used by an all-checks run: gcloud
// installed and credentials valid. Never prompts.
func (a *App) gsmLikelyAvailable(ctx context.Context) bool {
	return a.LookPath("gcloud") == nil && a.CheckADC(ctx) == nil
}
