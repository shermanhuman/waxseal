package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newDocsCmd generates the Markdown command reference. Hidden: it exists so
// docs/cli cannot drift from the code (CI regenerates and diffs it).
func newDocsCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:    "docs <dir>",
		Short:  "Write the Markdown command reference to a directory",
		Hidden: true,
		Args:   argsUsage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			root.DisableAutoGenTag = true
			return doc.GenMarkdownTree(root, args[0])
		},
	}
}
