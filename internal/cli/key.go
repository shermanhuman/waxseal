package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/ops"
	"github.com/shermanhuman/waxseal/internal/ui"
)

func newKeyCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key",
		Short:   "Add keys, set their values and change how they are managed",
		GroupID: groupSecrets,
	}
	cmd.AddCommand(newKeyAddCmd(app), newKeySetCmd(app), newKeyEditCmd(app))
	return cmd
}

// needsMutate is what every command that changes a secret needs.
func needsMutate() Needs { return Needs{Config: true, GSM: true, Kubeseal: true} }

func mutation(app *App, res *ops.MutationResult, summary string, next ...string) *mutationResult {
	return &mutationResult{Summary: summary, DryRun: res.DryRun, Changes: res.Changes, Next: next}
}

func commitNext(res *ops.MutationResult) []string {
	var paths []string
	for _, c := range res.Changes {
		if c.Kind == "metadata" || c.Kind == "manifest" {
			paths = append(paths, c.Target)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return []string{"commit the changed files: " + joinPaths(paths)}
}

func joinPaths(paths []string) string {
	s := ""
	for i, p := range paths {
		if i > 0 {
			s += " "
		}
		s += p
	}
	return s
}

// ── key add ────────────────────────────────────────────────────────────────

func newKeyAddCmd(app *App) *cobra.Command {
	var value valueFlags
	var kc keyConfigFlags
	var ns, name, manifest, scope, typ string
	cmd := &cobra.Command{
		Use:   "add [secret] [key]",
		Short: "Add a key; creates the secret if it does not exist",
		Long: `Store a new key's value in Secret Manager, record it in metadata and seal it
into the manifest. The value comes from --from-file (or - for stdin), from
--generate, or from a masked prompt on a terminal; it is never taken from
the command line.

When the secret is not registered yet it is created, which needs
--namespace; the manifest path, scope and type have defaults.`,
		Args:              argsUsage(cobra.MaximumNArgs(2)),
		ValidArgsFunction: app.completeSecretKey,
	}
	cmd.RunE = app.run(needsMutate(), func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
		svc, err := app.Service(ctx, needsMutate(), false)
		if err != nil {
			return nil, err
		}
		secretName, err := io.In.Choice(ui.Spec{Flag: "<secret>", Title: "Secret", Help: "an existing secret, or a new short name"},
			argSet(args, 0), argVal(args, 0), secretEnum(svc.ActiveSecretNames()), "")
		if err != nil {
			return nil, err
		}
		keyName, err := io.In.String(ui.Spec{Flag: "<key>", Title: "Key name"}, argSet(args, 1), argVal(args, 1), "", nonEmpty)
		if err != nil {
			return nil, err
		}

		var newSecret *ops.NewSecret
		if _, err := svc.Show(secretName); errors.Is(err, ops.ErrNotRegistered) {
			ns, err := io.In.String(ui.Spec{Flag: "--namespace", Title: "Namespace for the new secret " + secretName}, cmd.Flags().Changed("namespace"), ns, "", nonEmpty)
			if err != nil {
				return nil, err
			}
			if !cmd.Flags().Changed("namespace") {
				// Only a typo could get here non-interactively; on a terminal, confirm.
				if err := io.In.Confirm(fmt.Sprintf("create a new secret %q in namespace %s", secretName, ns)); err != nil {
					return nil, err
				}
			}
			scope, err := io.In.Choice(ui.Spec{Flag: "--scope", Title: "Scope"}, cmd.Flags().Changed("scope"), scope, core.Scopes, core.ScopeStrict)
			if err != nil {
				return nil, err
			}
			newSecret = &ops.NewSecret{Namespace: ns, Name: name, ManifestPath: manifest, Scope: scope, Type: typ}
		}

		spec, err := keySpec(cmd, io, app, &value, &kc, keyName)
		if err != nil {
			return nil, err
		}
		res, err := svc.AddKey(ctx, ops.AddKeyInput{ShortName: secretName, Key: spec, New: newSecret, DryRun: app.Flags.DryRun})
		if err != nil {
			return nil, err
		}
		return mutation(app, res, fmt.Sprintf("%s/%s stored as GSM version %s", secretName, keyName, res.Versions[keyName]), commitNext(res)...), nil
	})
	value.register(cmd)
	kc.register(cmd)
	cmd.Flags().StringVar(&ns, "namespace", "", "namespace of the new SealedSecret")
	cmd.Flags().StringVar(&name, "name", "", "name of the new SealedSecret (default: the short name)")
	cmd.Flags().StringVar(&manifest, "manifest", "", "manifest path for the new secret (default: apps/<secret>/sealed-secret.yaml)")
	enumFlag(cmd, &scope, "scope", "sealing scope of the new secret", core.Scopes)
	enumFlag(cmd, &typ, "type", "Kubernetes secret type of the new secret", core.SecretTypes)
	return cmd
}

// keySpec resolves value and configuration flags into an ops.KeySpec.
func keySpec(cmd *cobra.Command, io *IO, app *App, value *valueFlags, kc *keyConfigFlags, keyName string) (ops.KeySpec, error) {
	spec := ops.KeySpec{Name: keyName}
	if kc.template != "" {
		values, err := kc.paramMap()
		if err != nil {
			return spec, err
		}
		spec.Template = &ops.TemplateSpec{Template: kc.template, Values: values}
	}
	rotation, err := io.In.Choice(ui.Spec{Flag: "--rotation", Title: "How is " + keyName + " rotated?"},
		cmd.Flags().Changed("rotation") || value.generate, orDefault(kc.rotation, core.RotationGenerated, value.generate), core.RotationModes, core.RotationExternal)
	if err != nil {
		return spec, err
	}
	spec.Mode = rotation
	if rotation == core.RotationGenerated {
		kind, err := io.In.Choice(ui.Spec{Flag: "--generator", Title: "Generator"}, cmd.Flags().Changed("generator"), kc.generator, core.OfferedGeneratorKinds, core.GeneratorRandomBase64)
		if err != nil {
			return spec, err
		}
		spec.Generator = &core.GeneratorConfig{Kind: kind, Bytes: kc.bytes}
		if !value.generate && value.fromFile == "" {
			// A generated key gets a generated initial value.
			value.generate = true
		}
	}
	v, gen, err := value.resolve(io, app.Stdin, spec.Generator, ui.Spec{Flag: "--from-file or --generate", Title: "Value for " + keyName})
	if err != nil {
		return spec, err
	}
	spec.Value, spec.Generator = v, gen
	if spec.Value != nil && rotation == core.RotationGenerated {
		// Explicit value with a generated mode: keep the generator for future rotations.
		spec.Generator = &core.GeneratorConfig{Kind: kc.generator, Bytes: kc.bytes}
		if spec.Generator.Kind == "" {
			spec.Generator.Kind = core.GeneratorRandomBase64
		}
	}
	if kc.expires != "" {
		exp, err := parseExpiry(kc.expires)
		if err != nil {
			return spec, err
		}
		spec.ExpiresAt = exp
	}
	return spec, nil
}

func orDefault(v, def string, useDefault bool) string {
	if v == "" && useDefault {
		return def
	}
	return v
}

// ── key set ────────────────────────────────────────────────────────────────

func newKeySetCmd(app *App) *cobra.Command {
	var value valueFlags
	var expires string
	cmd := &cobra.Command{
		Use:   "set [secret] [key]",
		Short: "Store a new value for a key and reseal it",
		Long: `Store a new version of a key's value in Secret Manager and re-encrypt it
into the manifest. For a computed key the value is its {{secret}} part.

The value comes from --from-file (or - for stdin), from --generate for a
key with a generator, or from a masked prompt on a terminal.`,
		Args:              argsUsage(cobra.MaximumNArgs(2)),
		ValidArgsFunction: app.completeSecretKey,
	}
	cmd.RunE = app.run(needsMutate(), func(ctx context.Context, io *IO, args []string) (ui.Result, error) {
		svc, err := app.Service(ctx, needsMutate(), false)
		if err != nil {
			return nil, err
		}
		secretName, keyName, key, err := app.keyArgs(io, svc, args)
		if err != nil {
			return nil, err
		}
		var gen *core.GeneratorConfig
		if key.Generator != "" {
			gen = &core.GeneratorConfig{Kind: key.Generator}
		}
		v, gen, err := value.resolve(io, app.Stdin, gen, ui.Spec{Flag: "--from-file or --generate", Title: "New value for " + keyName})
		if err != nil {
			return nil, err
		}
		if gen != nil {
			if v, err = core.GenerateValue(gen); err != nil {
				return nil, err
			}
		}
		in := ops.SetKeyValueInput{ShortName: secretName, Key: keyName, Value: v, DryRun: app.Flags.DryRun}
		if key.ExpiresAt != "" || cmd.Flags().Changed("expires") {
			// A key that expires needs a new expiry with its new value.
			exp, err := io.In.String(ui.Spec{Flag: "--expires", Title: "New expiry (YYYY-MM-DD or none)"}, cmd.Flags().Changed("expires"), expires, "", nonEmpty)
			if err != nil {
				return nil, err
			}
			parsed, err := parseExpiry(exp)
			if err != nil {
				return nil, err
			}
			in.ExpiresAt = &parsed
		}
		res, err := svc.SetKeyValue(ctx, in)
		if err != nil {
			return nil, err
		}
		return mutation(app, res, fmt.Sprintf("%s/%s set to GSM version %s", secretName, keyName, res.Versions[keyName]), commitNext(res)...), nil
	})
	value.register(cmd)
	cmd.Flags().StringVar(&expires, "expires", "", "new expiry date (YYYY-MM-DD or RFC 3339), or 'none' to clear")
	return cmd
}

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
			in := ops.EditKeyInput{ShortName: secretName, Key: keyName}
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

// keyArgs resolves [secret] [key], picking from a terminal when missing.
func (a *App) keyArgs(io *IO, svc *ops.Service, args []string) (secretName, keyName string, key *ops.KeyView, err error) {
	secretName, err = a.secretArg(io, svc, args, 0)
	if err != nil {
		return "", "", nil, err
	}
	view, err := svc.Show(secretName)
	if err != nil {
		return "", "", nil, err
	}
	e := core.Enum{Name: "key"}
	for _, k := range view.Keys {
		e.Choices = append(e.Choices, core.Choice{Value: k.Name, Label: k.Name, Help: k.RotationMode})
	}
	keyName, err = io.In.Choice(ui.Spec{Flag: "<key>", Title: "Key"}, argSet(args, 1), argVal(args, 1), e, "")
	if err != nil {
		return "", "", nil, err
	}
	for i := range view.Keys {
		if view.Keys[i].Name == keyName {
			return secretName, keyName, &view.Keys[i], nil
		}
	}
	return "", "", nil, fmt.Errorf("%s/%s: %w", secretName, keyName, ops.ErrKeyNotFound)
}

func (a *App) completeSecretKey(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	switch len(args) {
	case 0:
		return a.completeSecret(cmd, args, toComplete)
	case 1:
		svc, err := a.Service(cmd.Context(), Needs{}, true)
		if err != nil {
			break
		}
		if view, err := svc.Show(args[0]); err == nil {
			var names []string
			for _, k := range view.Keys {
				names = append(names, k.Name)
			}
			return names, cobra.ShellCompDirectiveNoFileComp
		}
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

func argVal(args []string, i int) string { v, _ := ui.Arg(args, i); return v }
func argSet(args []string, i int) bool   { _, ok := ui.Arg(args, i); return ok }

func nonEmpty(v string) error {
	if v == "" {
		return errors.New("must not be empty")
	}
	return nil
}
