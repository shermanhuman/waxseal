package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/shermanhuman/waxseal/internal/core"
)

// enumValue is a pflag.Value backed by a core.Enum: it validates on Set,
// lists the allowed values in --help, and drives completion.
type enumValue struct {
	enum core.Enum
	dst  *string
	set  *bool
}

func (v *enumValue) String() string { return *v.dst }
func (v *enumValue) Type() string   { return "string" }
func (v *enumValue) Set(s string) error {
	if err := v.enum.Validate("--"+v.enum.Name, s); err != nil {
		return err
	}
	*v.dst = s
	if v.set != nil {
		*v.set = true
	}
	return nil
}

// enumFlag registers name as a flag whose values come from e.
func enumFlag(cmd *cobra.Command, dst *string, name, usage string, e core.Enum) {
	e.Name = name
	f := cmd.Flags()
	f.Var(&enumValue{enum: e, dst: dst}, name, usage+" ("+joinValues(e)+")")
	_ = cmd.RegisterFlagCompletionFunc(name, cobra.FixedCompletions(e.Values(), cobra.ShellCompDirectiveNoFileComp))
}

func joinValues(e core.Enum) string {
	s := ""
	for i, v := range e.Values() {
		if i > 0 {
			s += "|"
		}
		s += v
	}
	if e.Open {
		s += "|..."
	}
	return s
}

// secretEnum turns registered short names into the [secret] picker's
// choices. It is open: a name given on the command line is passed to ops,
// which reports an unregistered secret with a hint, rather than being
// rejected here as a usage error.
func secretEnum(names []string) core.Enum {
	e := core.Enum{Name: "secret", Open: true}
	for _, n := range names {
		e.Choices = append(e.Choices, core.Choice{Value: n, Label: n})
	}
	return e
}

var _ pflag.Value = (*enumValue)(nil)
