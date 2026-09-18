package cli2

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

func newSecretCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secret",
		Short:   "List, inspect and retire secrets",
		GroupID: groupSecrets,
	}
	cmd.AddCommand(newSecretListCmd(app), newSecretShowCmd(app))
	return cmd
}

// ── secret list ────────────────────────────────────────────────────────────

type listResult struct {
	Secrets []ops.SecretSummary `json:"secrets"`
	Errors  []string            `json:"errors,omitempty"`
}

func (r *listResult) Text(p *ui.Printer) {
	if len(r.Secrets) == 0 {
		p.Info("No secrets are registered. Run `waxseal discover` to find manifests.")
	} else {
		rows := make([][]string, 0, len(r.Secrets))
		for _, s := range r.Secrets {
			rows = append(rows, []string{s.ShortName, s.Namespace + "/" + s.Name, s.Status,
				strconv.Itoa(s.KeyCount), strings.Join(s.RotationModes, ","), s.Expiry})
		}
		p.Table([]string{"SECRET", "SEALEDSECRET", "STATUS", "KEYS", "ROTATION", "EXPIRY"}, rows)
	}
	for _, e := range r.Errors {
		p.Error("%s", e)
	}
}

func newSecretListCmd(app *App) *cobra.Command {
	var warnDays int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered secrets",
		Args:  argsUsage(cobra.NoArgs),
		RunE: app.run(Needs{Config: true}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
			svc, err := app.Service(ctx, Needs{}, false)
			if err != nil {
				return nil, err
			}
			rows, errs := svc.List(warnDays)
			r := &listResult{Secrets: rows}
			for _, e := range errs {
				r.Errors = append(r.Errors, e.Error())
			}
			return r, nil
		}),
	}
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "flag keys expiring within this many days")
	return cmd
}

// ── secret show ────────────────────────────────────────────────────────────

type showResult struct{ *ops.SecretView }

func (r *showResult) Text(p *ui.Printer) {
	v := r.SecretView
	pairs := [][2]string{
		{"Secret", v.ShortName},
		{"SealedSecret", v.Namespace + "/" + v.Name},
		{"Scope", v.Scope},
		{"Type", v.Type},
		{"Manifest", v.ManifestPath},
		{"Status", v.Status},
	}
	if v.Status == "retired" {
		pairs = append(pairs, [2]string{"Retired", v.RetiredAt + " " + v.RetireReason})
		if v.ReplacedBy != "" {
			pairs = append(pairs, [2]string{"Replaced by", v.ReplacedBy})
		}
	}
	p.KV(pairs)
	p.Println()
	rows := make([][]string, 0, len(v.Keys))
	for _, k := range v.Keys {
		expiry := ""
		if k.DaysLeft != nil {
			switch d := *k.DaysLeft; {
			case d < 0:
				expiry = fmt.Sprintf("expired %dd ago", -d)
			default:
				expiry = fmt.Sprintf("%dd left", d)
			}
		}
		gsm := ""
		if k.GSMResource != "" {
			gsm = k.GSMResource[strings.LastIndex(k.GSMResource, "/")+1:] + "@" + k.GSMVersion
		}
		rows = append(rows, []string{k.Name, k.Source, k.RotationMode, k.Generator, gsm, expiry})
	}
	p.Table([]string{"KEY", "SOURCE", "ROTATION", "GENERATOR", "GSM", "EXPIRY"}, rows)
}

func newSecretShowCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "show [secret]",
		Short:             "Show a secret's keys and where their values live",
		Args:              argsUsage(cobra.MaximumNArgs(1)),
		ValidArgsFunction: app.completeSecret,
		RunE: app.run(Needs{Config: true, Metadata: true}, func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
			svc, err := app.Service(ctx, Needs{}, false)
			if err != nil {
				return nil, err
			}
			name, err := app.secretArg(io, svc, args, 0)
			if err != nil {
				return nil, err
			}
			v, err := svc.Show(name)
			if err != nil {
				return nil, err
			}
			return &showResult{v}, nil
		}),
	}
	return cmd
}

// secretArg resolves the [secret] positional: given, or picked from the
// active secrets on a terminal.
func (a *App) secretArg(io *IO, svc *ops.Service, args []string, i int) (string, error) {
	val, set := ui.Arg(args, i)
	return io.In.Choice(ui.Spec{Flag: "<secret>", Title: "Secret"}, set, val, secretEnum(svc.ActiveSecretNames()), "")
}

func (a *App) completeSecret(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	svc, err := a.Service(cmd.Context(), Needs{}, true)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return svc.ActiveSecretNames(), cobra.ShellCompDirectiveNoFileComp
}
