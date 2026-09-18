package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// ── cert fetch ─────────────────────────────────────────────────────────────

type certResult struct{ *ops.CertStatus }

func (r *certResult) Text(p *ui.Printer) {
	switch {
	case r.Updated:
		p.Success("certificate stored (fingerprint %s)", r.ClusterFingerprint[:16])
		p.Next([]string{"re-encrypt every secret with it: waxseal reseal"})
	case r.Changed:
		p.Warn("certificate differs (repo %s, cluster %s); not written", short(r.RepoFingerprint), r.ClusterFingerprint[:16])
	default:
		p.Success("certificate is up to date (fingerprint %s)", r.ClusterFingerprint[:16])
	}
}

func newCertCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Manage the controller certificate", GroupID: groupSetup}
	cmd.AddCommand(&cobra.Command{
		Use:   "fetch",
		Short: "Fetch the controller's sealing certificate into the repo",
		Args:  argsUsage(cobra.NoArgs),
		RunE: app.run(Needs{Config: true, Kubeseal: true}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
			svc, err := app.Service(ctx, Needs{}, false)
			if err != nil {
				return nil, err
			}
			st, err := svc.RefreshCert(ctx, !app.Flags.DryRun)
			if err != nil {
				return nil, err
			}
			return &certResult{st}, nil
		}),
	})
	return cmd
}

// ── init ───────────────────────────────────────────────────────────────────

func newInitCmd(app *App) *cobra.Command {
	var project, controllerNS, controllerName string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write .waxseal/config.yaml for this repository",
		Long: `Create the waxseal configuration: the GCP project that holds the secrets
and where the sealed-secrets controller runs. Nothing else is touched;
fetch the certificate with ` + "`waxseal cert fetch`" + ` and register
manifests with ` + "`waxseal import`" + `.`,
		GroupID: groupSetup,
		Args:    argsUsage(cobra.NoArgs),
	}
	cmd.RunE = app.run(Needs{}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
		svc, err := app.Service(ctx, Needs{}, false)
		if err != nil {
			return nil, err
		}
		project, err := io.In.String(ui.Spec{Flag: "--project", Title: "GCP project ID", Help: "the project whose Secret Manager holds the values"},
			cmd.Flags().Changed("project"), project, "", nonEmpty)
		if err != nil {
			return nil, err
		}
		ns, err := io.In.String(ui.Spec{Flag: "--controller-namespace", Title: "Controller namespace"}, cmd.Flags().Changed("controller-namespace"), controllerNS, "kube-system", nonEmpty)
		if err != nil {
			return nil, err
		}
		name, err := io.In.String(ui.Spec{Flag: "--controller-name", Title: "Controller service name"}, cmd.Flags().Changed("controller-name"), controllerName, "sealed-secrets", nonEmpty)
		if err != nil {
			return nil, err
		}
		res, err := svc.Init(ops.InitInput{ProjectID: project, ControllerNamespace: ns, ControllerName: name, Force: force, DryRun: app.Flags.DryRun})
		if err != nil {
			return nil, err
		}
		return mutation(app, res, "initialised for project "+project,
			"fetch the controller certificate: waxseal cert fetch",
			"find existing manifests: waxseal discover"), nil
	})
	cmd.Flags().StringVar(&project, "project", "", "GCP project ID")
	cmd.Flags().StringVar(&controllerNS, "controller-namespace", "kube-system", "namespace of the sealed-secrets controller")
	cmd.Flags().StringVar(&controllerName, "controller-name", "sealed-secrets", "service name of the sealed-secrets controller")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	return cmd
}

// ── import ─────────────────────────────────────────────────────────────────

type importResult struct {
	Secrets []importOne `json:"secrets"`
	DryRun  bool        `json:"dryRun"`
}

type importOne struct {
	ShortName string `json:"shortName"`
	*ops.ImportResult
	Error string `json:"error,omitempty"`
}

func (r *importResult) Text(p *ui.Printer) {
	if len(r.Secrets) == 0 {
		p.Info("Every manifest is registered; name a secret to re-import it.")
		return
	}
	for _, s := range r.Secrets {
		if s.Error != "" {
			p.Error("%s: %s", s.ShortName, s.Error)
			continue
		}
		verb := "imported"
		if r.DryRun {
			verb = "would import"
		}
		p.Printf("%s %s: %d added, %d updated", verb, s.ShortName, len(s.Added), len(s.Updated))
		if len(s.Templated) > 0 {
			p.Printf(", templated: %s", strings.Join(s.Templated, " "))
		}
		p.Println()
		if len(s.MissingInCluster) > 0 {
			p.Warn("%s: in metadata but not in the cluster: %s", s.ShortName, strings.Join(s.MissingInCluster, ", "))
		}
		if len(s.Skipped) > 0 {
			p.Warn("%s: computed keys left unchanged (their cluster value is rendered): %s", s.ShortName, strings.Join(s.Skipped, ", "))
		}
	}
	if !r.DryRun {
		p.Next([]string{"review rotation modes: waxseal secret show <secret>; adjust with waxseal key edit", "commit .waxseal/metadata and the manifests"})
	}
}

func newImportCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [secret]...",
		Short: "Register manifests by reading their values from the cluster",
		Long: `Read each secret's plaintext from the cluster, store it in Secret Manager
and write metadata for it. Names are the ones ` + "`waxseal discover`" + ` suggests,
or registered secrets to re-import. Connection strings become computed
keys with the password as their {{secret}}. Every key is registered as
externally rotated; change that with ` + "`waxseal key edit`" + `.`,
		GroupID: groupSetup,
		Args:    argsUsage(cobra.ArbitraryArgs),
	}
	cmd.RunE = app.run(Needs{Config: true, GSM: true, Kubeseal: true, Kubectl: true}, func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
		svc, err := app.Service(ctx, Needs{GSM: true, Kubeseal: true, Kubectl: true}, false)
		if err != nil {
			return nil, err
		}
		names := args
		found, err := svc.Discover()
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			for _, d := range found {
				if d.Registered == "" {
					names = append(names, d.Suggested)
				}
			}
			if len(names) == 0 {
				return &importResult{DryRun: app.Flags.DryRun}, nil
			}
			if err := io.In.Confirm("import " + strings.Join(names, ", ")); err != nil {
				return nil, err
			}
		}
		out := &importResult{DryRun: app.Flags.DryRun}
		failed := 0
		err = io.P.Spin(ctx, "Importing", func(progress func(string)) error {
			for _, name := range names {
				progress(name)
				one := importOne{ShortName: name}
				res, err := svc.Import(ctx, ops.ImportInput{ShortName: name, Discovered: found, DryRun: app.Flags.DryRun})
				if err != nil {
					one.Error = err.Error()
					failed++
				} else {
					one.ImportResult = res
				}
				out.Secrets = append(out.Secrets, one)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if failed > 0 {
			return out, &ExitError{Code: ExitFailure}
		}
		return out, nil
	})
	return cmd
}
