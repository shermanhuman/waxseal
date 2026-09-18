// Package cli2 is the cobra layer: it turns flags and arguments into
// inputs, calls ops, and renders results. It contains no domain logic.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/shermanhuman/waxseal/internal/kube"
	"github.com/shermanhuman/waxseal/internal/logging"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/proc"
	"github.com/shermanhuman/waxseal/internal/reminder"
	"github.com/shermanhuman/waxseal/internal/repo"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// GlobalFlags are the persistent flags on the root command.
type GlobalFlags struct {
	Repo    string
	DryRun  bool
	Yes     bool
	NoInput bool
	NoColor bool
	Verbose bool
	Output  string
}

// App holds the process environment and the factories for external ports.
// Tests replace the factories with fakes; everything is built lazily so
// --help and offline commands never touch credentials.
type App struct {
	Flags  GlobalFlags
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	IsTTY  func(any) bool
	Now    func() time.Time

	// Factories and ports. Nil means "use the real one".
	NewStore  func(ctx context.Context, projectID string) (store.Store, func(), error)
	NewSealer func(certPath string) seal.Sealer
	Cluster   ops.Cluster
	Certs     ops.CertFetcher
	Gcloud    *gcp.Client
	// NewReminders builds the configured reminder provider.
	NewReminders func(ctx context.Context, cfg *config.RemindersConfig) (reminder.Provider, error)
	Prompter     ui.Prompter
	// LookPath reports whether a binary is installed.
	LookPath func(name string) error
	// CheckADC reports whether GCP application default credentials work.
	CheckADC func(ctx context.Context) error

	// memoised
	repo       *repo.Repo
	cfg        *config.Config
	st         store.Store
	closeStore func()
}

// NewApp returns an App wired to the real process environment.
func NewApp() *App {
	return &App{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
		IsTTY:  ui.IsTerminal,
		Now:    time.Now,
		NewStore: func(ctx context.Context, projectID string) (store.Store, func(), error) {
			s, err := store.NewGSMStore(ctx, projectID)
			if err != nil {
				return nil, nil, err
			}
			return s, func() { _ = s.Close() }, nil
		},
		NewSealer:    func(certPath string) seal.Sealer { return seal.NewKubesealSealer(certPath) },
		Cluster:      kube.Client{},
		Certs:        seal.Kubeseal{},
		Gcloud:       &gcp.Client{},
		NewReminders: reminder.New,
		LookPath:     proc.LookPath,
		CheckADC:     gcp.ADCTokenValid,
	}
}

// Close releases anything the run opened.
func (a *App) Close() {
	if a.closeStore != nil {
		a.closeStore()
		a.closeStore = nil
	}
}

// IO is what a command uses to talk to the user.
type IO struct {
	In *ui.Inputs
	P  *ui.Printer
}

func (a *App) newIO(ctx context.Context, cmd *cobra.Command) *IO {
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
	interactive := ui.Interactive(a.Flags.NoInput, a.Getenv, a.IsTTY, a.Stdin, errw)
	p := a.Prompter
	if p == nil && interactive {
		p = ui.NewPrompter(ctx, a.Stdin, errw, a.Getenv("ACCESSIBLE") != "")
	}
	return &IO{
		In: ui.NewInputs(interactive, a.Flags.Yes, p),
		P: ui.NewPrinter(out, errw,
			ui.ColorEnabled(a.Flags.NoColor, a.Getenv, a.IsTTY, out),
			ui.ColorEnabled(a.Flags.NoColor, a.Getenv, a.IsTTY, errw),
			a.IsTTY(errw)),
	}
}

// Needs declares what a command must have before its body runs.
type Needs struct {
	Config, Metadata, GSM, Kubeseal, Kubectl, Gcloud bool
}

// runFunc is a command body: resolve inputs, call ops, return a result. A
// result is rendered even when an error accompanies it, which is how a
// failed check shows its findings and still exits non-zero.
type runFunc func(ctx context.Context, io *IO, args []string) (ui.Result, error)

// run wraps a command body with preflight, IO construction and rendering.
func (a *App) run(n Needs, fn runFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if a.Flags.Verbose {
			logging.SetLevel(slog.LevelDebug)
		}
		io := a.newIO(ctx, cmd)
		if err := a.preflight(ctx, io, n); err != nil {
			return err
		}
		result, err := fn(ctx, io, args)
		if result != nil {
			if renderErr := a.render(cmd, io, result); renderErr != nil {
				return renderErr
			}
		}
		return err
	}
}

func (a *App) render(cmd *cobra.Command, io *IO, result ui.Result) error {
	if result == nil {
		return nil
	}
	if a.Flags.Output == "json" {
		return writeJSON(cmd.OutOrStdout(), result)
	}
	result.Text(io.P)
	return nil
}

// Repo returns the repository at --repo.
func (a *App) Repo() (*repo.Repo, error) {
	if a.repo == nil {
		r, err := repo.Open(a.Flags.Repo)
		if err != nil {
			return nil, err
		}
		a.repo = r
	}
	return a.repo, nil
}

// Config loads the config once. A missing config points the user at init.
func (a *App) Config() (*config.Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	r, err := a.Repo()
	if err != nil {
		return nil, err
	}
	cfg, err := r.Config()
	if err != nil {
		if core.IsNotFound(err) {
			return nil, ui.WithHint(fmt.Errorf("waxseal is not initialised in %s", r.Root()), "run `waxseal init`")
		}
		return nil, err
	}
	a.cfg = cfg
	return cfg, nil
}

// Store opens the GSM store once.
func (a *App) Store(ctx context.Context) (store.Store, error) {
	if a.st != nil {
		return a.st, nil
	}
	cfg, err := a.Config()
	if err != nil {
		return nil, err
	}
	st, closeFn, err := a.NewStore(ctx, cfg.Store.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("open Secret Manager for %s: %w", cfg.Store.ProjectID, err)
	}
	a.st, a.closeStore = st, closeFn
	return st, nil
}

// Sealer returns a sealer bound to the repo's certificate.
func (a *App) Sealer() (seal.Sealer, error) {
	cfg, err := a.Config()
	if err != nil {
		return nil, err
	}
	r, _ := a.Repo()
	if _, err := r.Cert(cfg.Cert.RepoCertPath); err != nil {
		if core.IsNotFound(err) {
			return nil, ui.WithHint(err, "run `waxseal cert fetch`")
		}
		return nil, err
	}
	return a.NewSealer(r.Root() + "/" + cfg.Cert.RepoCertPath), nil
}

// Service assembles an ops.Service with the ports n asks for. With
// optional set, unavailable ports are left nil instead of failing, which
// is how `check` with no arguments degrades gracefully.
func (a *App) Service(ctx context.Context, n Needs, optional bool) (*ops.Service, error) {
	r, err := a.Repo()
	if err != nil {
		return nil, err
	}
	svc := &ops.Service{Repo: r, Now: a.Now, Certs: a.Certs}
	if cfg, err := a.Config(); err == nil {
		svc.Config, svc.ProjectID = cfg, cfg.Store.ProjectID
	}
	if n.GSM {
		st, err := a.Store(ctx)
		if err != nil && !optional {
			return nil, err
		}
		if err == nil {
			svc.Store = st
		}
	}
	if n.Kubeseal {
		s, err := a.Sealer()
		if err != nil && !optional {
			return nil, err
		}
		if err == nil {
			svc.Sealer = s
		}
	}
	if n.Kubectl {
		svc.Cluster = a.Cluster
	}
	return svc, nil
}

// preflight checks tools and credentials before a command body runs, so
// the user gets one clear message instead of a gRPC error mid-run.
func (a *App) preflight(ctx context.Context, io *IO, n Needs) error {
	if n.Config || n.Metadata || n.GSM || n.Kubeseal {
		if _, err := a.Config(); err != nil {
			return err
		}
	}
	if n.Metadata {
		r, _ := a.Repo()
		if secrets, _ := r.AllMetadata(); len(secrets) == 0 {
			return ui.WithHint(errors.New("no secrets are registered"), "run `waxseal discover`, then `waxseal import`, or `waxseal key add`")
		}
	}
	for _, tool := range []struct {
		needed bool
		name   string
		url    string
	}{
		{n.Kubeseal, "kubeseal", "https://github.com/bitnami-labs/sealed-secrets/releases"},
		{n.Kubectl, "kubectl", "https://kubernetes.io/docs/tasks/tools/"},
		{n.Gcloud || n.GSM, "gcloud", "https://cloud.google.com/sdk/docs/install"},
	} {
		if tool.needed {
			if err := a.LookPath(tool.name); err != nil {
				return ui.WithHint(err, "install it from "+tool.url)
			}
		}
	}
	if n.GSM {
		if err := a.CheckADC(ctx); err != nil {
			if io.In.Offer("GCP credentials are missing or expired. Run `gcloud auth application-default login` now") {
				if err := a.Gcloud.Interactive(ctx, "auth", "application-default", "login"); err != nil {
					return err
				}
				if err := a.CheckADC(ctx); err == nil {
					io.P.Success("GCP credentials refreshed")
					return nil
				}
			}
			return ui.WithHint(fmt.Errorf("GCP credentials unavailable: %w", err), "run `gcloud auth application-default login`")
		}
	}
	return nil
}
