package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

// ── key edit ───────────────────────────────────────────────────────────────

func newKeyEditCmd(app *App) *cobra.Command {
	var kc keyConfigFlags
	cmd := &cobra.Command{
		Use:   "edit [secret] [key]",
		Short: "Change how a key is managed: rotation, generator, expiry, template",
		Long: `Change a key's rotation mode, generator or expiry (metadata only), or a
computed key's template and values (stores a new payload version and
reseals; the secret part is untouched).`,
		Args:              argsUsage(cobra.MaximumNArgs(2)),
		ValidArgsFunction: app.completeSecretKey,
	}
	cmd.RunE = app.run(Needs{Config: true, Metadata: true}, func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
		svc, err := app.Service(ctx, Needs{}, false)
		if err != nil {
			return nil, err
		}
		secretName, keyName, _, err := app.keyArgs(io, svc, args)
		if err != nil {
			return nil, err
		}
		computedChange := cmd.Flags().Changed("template") || len(kc.params) > 0
		metaChange := cmd.Flags().Changed("rotation") || cmd.Flags().Changed("generator") || cmd.Flags().Changed("expires")
		if !computedChange && !metaChange {
			rotation, err := io.In.Choice(ui.Spec{Flag: "--rotation, --generator, --expires, --template or --param", Title: "Rotation mode"},
				false, "", core.RotationModes, "")
			if err != nil {
				return nil, err
			}
			kc.rotation, metaChange = rotation, true
		}

		var last *ops.MutationResult
		if metaChange {
			in := ops.EditKeyInput{ShortName: secretName, Key: keyName, DryRun: app.Flags.DryRun}
			if cmd.Flags().Changed("rotation") || kc.rotation != "" {
				in.Rotation = &kc.rotation
			}
			if cmd.Flags().Changed("generator") || cmd.Flags().Changed("bytes") {
				kind, err := io.In.Choice(ui.Spec{Flag: "--generator", Title: "Generator"}, kc.generator != "", kc.generator, core.OfferedGeneratorKinds, core.GeneratorRandomBase64)
				if err != nil {
					return nil, err
				}
				in.Generator = &core.GeneratorConfig{Kind: kind, Bytes: kc.bytes}
			} else if kc.rotation == core.RotationGenerated {
				kind, err := io.In.Choice(ui.Spec{Flag: "--generator", Title: "Generator"}, false, "", core.OfferedGeneratorKinds, core.GeneratorRandomBase64)
				if err != nil {
					return nil, err
				}
				in.Generator = &core.GeneratorConfig{Kind: kind, Bytes: kc.bytes}
			}
			if cmd.Flags().Changed("expires") {
				exp, err := parseExpiry(kc.expires)
				if err != nil {
					return nil, err
				}
				in.ExpiresAt = &exp
			}
			if last, err = svc.EditKey(in); err != nil {
				return nil, err
			}
		}
		if computedChange {
			msvc, err := app.Service(ctx, needsMutate(), false)
			if err != nil {
				return nil, err
			}
			values, err := kc.paramMap()
			if err != nil {
				return nil, err
			}
			in := ops.UpdateComputedInput{ShortName: secretName, Key: keyName, Values: values, DryRun: app.Flags.DryRun}
			if cmd.Flags().Changed("template") {
				in.Template = &kc.template
			}
			res, err := msvc.UpdateComputed(ctx, in)
			if err != nil {
				return nil, err
			}
			if last != nil {
				res.Changes = append(last.Changes, res.Changes...)
			}
			last = res
		}
		return mutation(app, last, fmt.Sprintf("%s/%s updated", secretName, keyName), commitNext(last)...), nil
	})
	kc.register(cmd)
	return cmd
}
