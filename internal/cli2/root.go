package cli2

import (
	"cmp"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/version"
)

const (
	groupSecrets = "secrets"
	groupOps     = "ops"
	groupSetup   = "setup"
)

func newRootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "waxseal",
		Short: "Manage SealedSecrets with Google Secret Manager as the source of truth",
		Long: `waxseal keeps the plaintext of every Kubernetes secret in Google Secret
Manager and only ciphertext in Git. Metadata under .waxseal/ pins each key
to a GSM secret and version, so manifests can be re-sealed at any time.

Every command can be driven entirely by flags. On a terminal, waxseal
prompts for whatever you leave out; with --no-input or in CI it fails
instead, naming the missing flag.`,
		Version:       version.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: false,
		},
	}
	root.SetVersionTemplate(version.String())
	root.SetFlagErrorFunc(flagErrorFunc)

	f := root.PersistentFlags()
	f.StringVar(&app.Flags.Repo, "repo", cmp.Or(app.Flags.Repo, "."), "path to the repository")
	f.BoolVar(&app.Flags.DryRun, "dry-run", false, "show what would change without changing anything")
	f.BoolVarP(&app.Flags.Yes, "yes", "y", false, "answer yes to confirmations")
	f.BoolVar(&app.Flags.NoInput, "no-input", false, "never prompt; fail if an input is missing")
	f.StringVarP(&app.Flags.Output, "output", "o", "text", "output format: text or json")
	f.BoolVar(&app.Flags.NoColor, "no-color", false, "disable colour")
	f.BoolVar(&app.Flags.Verbose, "verbose", false, "log subprocess calls and debug detail to stderr")
	_ = root.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp))

	root.AddGroup(
		&cobra.Group{ID: groupSecrets, Title: "Secrets and keys:"},
		&cobra.Group{ID: groupOps, Title: "Operations:"},
		&cobra.Group{ID: groupSetup, Title: "Setup:"},
	)
	root.AddCommand(
		newSecretCmd(app),
		newKeyCmd(app),
		newRotateCmd(app),
		newResealCmd(app),
		newCheckCmd(app),
		newRemindersCmd(app),
		newInitCmd(app),
		newGCPCmd(app),
		newCertCmd(app),
		newDiscoverCmd(app),
		newImportCmd(app),
		newSetupCmd(app),
	)
	root.SetHelpCommandGroupID(groupSetup)
	root.SetCompletionCommandGroupID(groupSetup)

	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if o := app.Flags.Output; o != "text" && o != "json" {
			return &usageError{err: errInvalidOutput(o)}
		}
		return nil
	}
	return root
}
