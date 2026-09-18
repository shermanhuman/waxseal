package cli2

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/testutil"
)

// walk visits every command in the tree, leaves and parents alike.
func walk(cmd *cobra.Command, fn func(*cobra.Command)) {
	fn(cmd)
	for _, c := range cmd.Commands() {
		if c.Hidden || c.Name() == "completion" || c.Name() == "help" {
			continue
		}
		walk(c, fn)
	}
}

func commandPath(cmd *cobra.Command) string {
	return strings.ReplaceAll(cmd.CommandPath(), " ", "_")
}

// TestHelpGolden pins the whole command surface: every command's --help
// output is a golden file. A new command without a golden fails; a removed
// command leaves an orphan golden, which also fails.
func TestHelpGolden(t *testing.T) {
	root := newRootCmd(NewApp())
	seen := map[string]bool{}
	walk(root, func(cmd *cobra.Command) {
		name := commandPath(cmd)
		seen[name+".golden"] = true
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(append(strings.Fields(cmd.CommandPath())[1:], "--help"))
			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("--help failed: %v", err)
			}
			testutil.AssertGolden(t, filepath.Join("testdata", "help", name+".golden"), out.Bytes())
		})
	})

	goldens, _ := filepath.Glob(filepath.Join("testdata", "help", "*.golden"))
	for _, g := range goldens {
		if !seen[filepath.Base(g)] {
			t.Errorf("orphan golden %s: the command no longer exists; delete the file", g)
		}
	}
}

// TestNoInputContract runs every leaf command non-interactively with no
// flags and no arguments. Each must either succeed or fail with exit 2 and
// name what is missing; none may hang, prompt, or crash.
func TestNoInputContract(t *testing.T) {
	// Commands that legitimately run with no input at all.
	succeeds := map[string]bool{
		"waxseal":             true, // prints help
		"waxseal secret":      true,
		"waxseal secret list": true,
		"waxseal check":       true,
		"waxseal discover":    true,
	}
	ta := newTestApp(t, false)
	ta.seedStore(t)
	walk(newRootCmd(NewApp()), func(cmd *cobra.Command) {
		if cmd.HasSubCommands() && !cmd.Runnable() {
			return
		}
		path := cmd.CommandPath()
		t.Run(strings.ReplaceAll(path, " ", "_"), func(t *testing.T) {
			args := append(strings.Fields(path)[1:], "--no-input")
			_, stderr, code := ta.run(args...)
			switch {
			case succeeds[path]:
				if code != ExitOK {
					t.Errorf("exit %d, want 0; stderr:\n%s", code, stderr)
				}
			default:
				if code != ExitUsage {
					t.Errorf("exit %d, want 2 (missing input); stderr:\n%s", code, stderr)
				}
				if !strings.Contains(stderr, "missing required") && !strings.Contains(stderr, "confirmation required") {
					t.Errorf("stderr must name what is missing:\n%s", stderr)
				}
			}
		})
	})
}
