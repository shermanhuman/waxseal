package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/reminder"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// ── gcp provision ──────────────────────────────────────────────────────────

type provisionResult struct {
	Project string     `json:"project"`
	Steps   []gcp.Step `json:"steps"`
	DryRun  bool       `json:"dryRun"`
}

func (r *provisionResult) Text(p *ui.Printer) {
	verb := "ran"
	if r.DryRun {
		verb = "would run"
	}
	for _, s := range r.Steps {
		p.Printf("%s: gcloud %s\n", s.Desc, strings.Join(s.Args, " "))
	}
	p.Println(fmt.Sprintf("%s %d gcloud steps for project %s", verb, len(r.Steps), r.Project))
	if !r.DryRun {
		p.Next([]string{"initialise the repo: waxseal init --project " + r.Project})
	}
}

func newGCPCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "gcp", Short: "Provision GCP for waxseal", GroupID: groupSetup}

	var p gcp.BootstrapParams
	var create bool
	provision := &cobra.Command{
		Use:   "provision",
		Short: "Enable APIs and create the service account waxseal needs",
		Long: `Run the gcloud steps that prepare a project: enable Secret Manager (and
the Calendar and Tasks APIs with --enable-reminders-api), create a service
account with Secret Manager admin, and optionally a Workload Identity pool
for GitHub Actions. With --create the project itself is created first,
which needs a billing account and a folder or organization.

Steps that are already done are skipped. --dry-run prints the plan.`,
		Args: argsUsage(cobra.NoArgs),
	}
	provision.RunE = app.run(Needs{Gcloud: true}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
		var err error
		p.ProjectID, err = io.In.String(ui.Spec{Flag: "--project", Title: "GCP project ID"}, cmd.Flags().Changed("project") || provision.Flags().Changed("project"), p.ProjectID, "", nonEmpty)
		if err != nil {
			return nil, err
		}
		p.CreateProject = create
		if !create && io.In.Interactive && !provision.Flags().Changed("create") {
			p.CreateProject = io.In.Offer("Create project " + p.ProjectID + " (it does not exist yet)")
		}
		if p.CreateProject {
			accounts := core.Enum{Name: "billing account", Open: true}
			if list, err := app.Gcloud.BillingAccounts(ctx); err == nil {
				for _, a := range list {
					if a.Open {
						accounts.Choices = append(accounts.Choices, core.Choice{Value: strings.TrimPrefix(a.Name, "billingAccounts/"), Label: a.DisplayName})
					}
				}
			}
			p.BillingAccountID, err = io.In.Choice(ui.Spec{Flag: "--billing-account", Title: "Billing account"}, provision.Flags().Changed("billing-account"), p.BillingAccountID, accounts, "")
			if err != nil {
				return nil, err
			}
			if p.FolderID == "" && p.OrganizationID == "" {
				orgs := core.Enum{Name: "organization", Open: true}
				if list, err := app.Gcloud.Organizations(ctx); err == nil {
					for _, o := range list {
						orgs.Choices = append(orgs.Choices, core.Choice{Value: strings.TrimPrefix(o.Name, "organizations/"), Label: o.DisplayName})
					}
				}
				p.OrganizationID, err = io.In.Choice(ui.Spec{Flag: "--organization or --folder", Title: "Organization (or folder ID)"}, false, "", orgs, "")
				if err != nil {
					return nil, err
				}
			}
		}
		steps := gcp.BootstrapPlan(p)
		out := &provisionResult{Project: p.ProjectID, Steps: steps, DryRun: app.Flags.DryRun}
		if app.Flags.DryRun {
			return out, nil
		}
		if err := io.In.Confirm(fmt.Sprintf("run %d gcloud steps against project %s", len(steps), p.ProjectID)); err != nil {
			return nil, err
		}
		err = app.Gcloud.Apply(ctx, steps, func(s gcp.Step, err error) {
			if err == nil {
				io.P.Success("%s", s.Desc)
			}
		})
		if errors.Is(err, gcp.ErrProjectIDTaken) {
			return nil, ui.WithHint(err, "project IDs are global; pick another with --project")
		}
		if err != nil {
			return nil, err
		}
		return out, nil
	})
	provision.Flags().StringVar(&p.ProjectID, "project", "", "GCP project ID")
	provision.Flags().BoolVar(&create, "create", false, "create the project first")
	provision.Flags().StringVar(&p.BillingAccountID, "billing-account", "", "billing account to link to a created project")
	provision.Flags().StringVar(&p.OrganizationID, "organization", "", "organization ID for a created project")
	provision.Flags().StringVar(&p.FolderID, "folder", "", "folder ID for a created project")
	provision.MarkFlagsMutuallyExclusive("organization", "folder")
	provision.Flags().StringVar(&p.ServiceAccountID, "service-account", "waxseal", "service account ID to create")
	provision.Flags().StringVar(&p.GitHubRepo, "github-repo", "", "owner/repo to set up Workload Identity for GitHub Actions")
	provision.Flags().BoolVar(&p.EnableReminders, "enable-reminders-api", false, "also enable the Calendar and Tasks APIs")
	cmd.AddCommand(provision)
	return cmd
}

// ── reminders ──────────────────────────────────────────────────────────────

type syncResult struct{ *ops.SyncResult }

func (r *syncResult) Text(p *ui.Printer) {
	if len(r.Secrets) == 0 {
		p.Info("No secrets have expiry dates; nothing to sync.")
		return
	}
	if r.DryRun {
		p.Printf("would sync reminders for %s\n", strings.Join(r.Secrets, ", "))
		return
	}
	p.Printf("reminders: %d created, %d updated, %d skipped\n", r.Created, r.Updated, r.Skipped)
	for _, e := range r.Errors {
		p.Error("%s", e)
	}
}

func newRemindersCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "reminders", Short: "Expiry reminders in Google Tasks or Calendar", GroupID: groupOps}

	cmd.AddCommand(&cobra.Command{
		Use:   "sync",
		Short: "Create or update reminders for every key with an expiry",
		Args:  argsUsage(cobra.NoArgs),
		RunE: app.run(Needs{Config: true, GSM: true}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
			svc, provider, err := app.remindersService(ctx)
			if err != nil {
				return nil, err
			}
			res, err := svc.SyncReminders(ctx, provider, app.Flags.DryRun)
			if err != nil {
				return nil, err
			}
			return &syncResult{res}, nil
		}),
	})

	cmd.AddCommand(&cobra.Command{
		Use:               "clear [secret]",
		Short:             "Remove a secret's reminders",
		Args:              argsUsage(cobra.MaximumNArgs(1)),
		ValidArgsFunction: app.completeSecret,
		RunE: app.run(Needs{Config: true, Metadata: true, GSM: true}, func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
			svc, provider, err := app.remindersService(ctx)
			if err != nil {
				return nil, err
			}
			name, err := app.secretArg(io, svc, args, 0)
			if err != nil {
				return nil, err
			}
			if err := svc.ClearReminders(ctx, provider, name, app.Flags.DryRun); err != nil {
				return nil, err
			}
			return &mutationResult{Summary: "cleared reminders for " + name, DryRun: app.Flags.DryRun,
				Changes: []ops.Change{{Op: "delete", Kind: "reminder", Target: name}}}, nil
		}),
	})

	var provider, tasklist, calendar, leadDays string
	configure := &cobra.Command{
		Use:   "configure",
		Short: "Enable reminders and choose where they go",
		Args:  argsUsage(cobra.NoArgs),
	}
	configure.RunE = app.run(Needs{Config: true}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
		r, err := app.Repo()
		if err != nil {
			return nil, err
		}
		cfg, err := app.Config()
		if err != nil {
			return nil, err
		}
		provider, err := io.In.Choice(ui.Spec{Flag: "--provider", Title: "Where should reminders go?"}, configure.Flags().Changed("provider"), provider, core.ReminderProviders, "tasks")
		if err != nil {
			return nil, err
		}
		rc := &config.RemindersConfig{Enabled: provider != "none", Provider: provider}
		if provider != "none" {
			days, err := io.In.String(ui.Spec{Flag: "--lead-days", Title: "Days before expiry to remind", Help: "comma-separated, e.g. 30,7,1"},
				configure.Flags().Changed("lead-days"), leadDays, "30,7,1", func(v string) error { _, err := parseIntList(v); return err })
			if err != nil {
				return nil, err
			}
			rc.LeadTimeDays, _ = parseIntList(days)
			if provider == "tasks" || provider == "both" {
				rc.TasklistID, err = io.In.String(ui.Spec{Flag: "--tasklist", Title: "Task list ID", Help: "@default is your primary list"}, configure.Flags().Changed("tasklist"), tasklist, "@default", nonEmpty)
				if err != nil {
					return nil, err
				}
			}
			if provider == "calendar" || provider == "both" {
				rc.CalendarID, err = io.In.String(ui.Spec{Flag: "--calendar", Title: "Calendar ID", Help: "primary, or a calendar's email address"}, configure.Flags().Changed("calendar"), calendar, "primary", nonEmpty)
				if err != nil {
					return nil, err
				}
			}
		}
		cfg.Reminders = rc
		res := &ops.MutationResult{DryRun: app.Flags.DryRun, Changes: []ops.Change{{Op: "update", Kind: "config", Target: repo.ConfigRel}}}
		if !app.Flags.DryRun {
			if err := r.WriteConfig(cfg); err != nil {
				return nil, err
			}
		}
		next := []string{}
		if rc.Enabled {
			next = append(next, "create the reminders: waxseal reminders sync")
		}
		return mutation(app, res, "reminders provider set to "+provider, next...), nil
	})
	enumFlag(configure, &provider, "provider", "where reminders are created", core.ReminderProviders)
	configure.Flags().StringVar(&tasklist, "tasklist", "@default", "Google Tasks list ID")
	configure.Flags().StringVar(&calendar, "calendar", "primary", "Google Calendar ID")
	configure.Flags().StringVar(&leadDays, "lead-days", "30,7,1", "days before expiry to remind, comma-separated")
	cmd.AddCommand(configure)
	return cmd
}

func (a *App) remindersService(ctx context.Context) (*ops.Service, reminder.Provider, error) {
	svc, err := a.Service(ctx, Needs{}, false)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := a.Config()
	if err != nil {
		return nil, nil, err
	}
	provider, err := a.NewReminders(ctx, cfg.Reminders)
	if errors.Is(err, reminder.ErrDisabled) {
		return nil, nil, ui.WithHint(err, "enable them with `waxseal reminders configure`")
	}
	if err != nil {
		return nil, nil, err
	}
	return svc, provider, nil
}

// ── setup ──────────────────────────────────────────────────────────────────

func newSetupCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Guided first-time setup (interactive)",
		Long: `Walk through first-time setup on a terminal: init, optionally provision
GCP, fetch the certificate, discover manifests, import them, and configure
reminders. Each step is an ordinary command; this only sequences them and
asks for what is missing. In scripts, run the steps directly.`,
		GroupID: groupSetup,
		Args:    argsUsage(cobra.NoArgs),
		RunE: app.run(Needs{}, func(ctx context.Context, io *IO, _ []string) (ui.Result, error) {
			if !io.In.Interactive {
				return nil, ui.WithHint(&usageError{err: errors.New("setup is interactive; run it on a terminal")},
					"in scripts run: waxseal init, waxseal gcp provision, waxseal cert fetch, waxseal discover, waxseal import, waxseal reminders configure")
			}
			root := newRootCmd(app)
			step := func(args ...string) error {
				io.P.Info("")
				io.P.Info("── waxseal %s", strings.Join(args, " "))
				root.SetArgs(args)
				return root.ExecuteContext(ctx)
			}
			if _, err := app.Config(); err == nil {
				io.P.Info("waxseal is already initialised here; steps that are done are skipped.")
			} else if err := step("init"); err != nil {
				return nil, err
			}
			if io.In.Offer("Provision GCP (enable APIs, create the service account) now") {
				cfg, _ := app.Config()
				if err := step("gcp", "provision", "--project", cfg.Store.ProjectID); err != nil {
					return nil, err
				}
			}
			if err := step("cert", "fetch"); err != nil {
				io.P.Warn("%v", err)
				io.P.Info("fetch it later with: waxseal cert fetch")
			}
			if err := step("discover"); err != nil {
				return nil, err
			}
			if io.In.Offer("Import the unregistered manifests from the cluster now") {
				if err := step("import"); err != nil {
					io.P.Warn("%v", err)
				}
			}
			if io.In.Offer("Configure expiry reminders") {
				if err := step("reminders", "configure"); err != nil {
					return nil, err
				}
			}
			io.P.Next([]string{"commit .waxseal/ and keys/", "check everything: waxseal check"})
			return nil, nil
		}),
	}
}
