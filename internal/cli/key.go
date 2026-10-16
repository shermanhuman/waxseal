package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// mutation renders an ops result. Copies of a changed key get the command
// that re-copies each, after next; keys that stopped being copies are
// noted in the summary.
func mutation(app *App, res *ops.MutationResult, summary string, next ...string) *mutationResult {
	for _, d := range res.Detached {
		summary += fmt.Sprintf("; %s/%s is no longer a copy of %s/%s", d.Target.ShortName, d.Target.KeyName, d.Source.ShortName, d.Source.KeyName)
	}
	for _, c := range res.Copies {
		next = append(next, fmt.Sprintf("re-copy into %s/%s: waxseal key set %s %s --from-key %s/%s",
			c.Target.ShortName, c.Target.KeyName, c.Target.ShortName, c.Target.KeyName, c.Source.ShortName, c.Source.KeyName))
	}
	return &mutationResult{Summary: summary, DryRun: res.DryRun, Changes: res.Changes, Next: next, Copies: res.Copies, Detached: res.Detached}
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
	return []string{"commit the changed files: " + strings.Join(paths, " ")}
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
--generate, from --from-key, or from a masked prompt on a terminal; it is
never taken from the command line.

--from-key <secret>/<key> copies another registered key, in any namespace
and retired or not: its pinned Secret Manager version is copied into this
key's own Secret Manager secret, and its kind, template, rotation and expiry
come with it (--rotation and --expires override them). The copy is recorded
as copiedFrom; when the source changes, re-copy with
` + "`waxseal key set <secret> <key> --from-key <source>/<key>`" + `.

With --template, the stored value is the template's {{secret}} part, so
--generate makes values of a fixed shape. A keyring that rotates by adding
entries must not be rotated by waxseal; give it --rotation static:

  waxseal key add app ENCRYPTION_KEYS --template 'v1:{{secret}}' \
    --generate --generator randomBase64 --bytes 32 --rotation static

When the secret is not registered yet it is created, which needs
--namespace; the manifest path and scope have defaults, and the type
defaults to Opaque, or to the source secret's type with --from-key.`,
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
		summary := fmt.Sprintf("%s/%s stored as GSM version %s", secretName, keyName, res.Versions[keyName])
		if spec.CopyFrom != nil {
			summary = fmt.Sprintf("%s/%s copied from %s/%s", secretName, keyName, spec.CopyFrom.ShortName, spec.CopyFrom.KeyName)
		}
		return mutation(app, res, summary, commitNext(res)...), nil
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
	from, err := value.copyRef()
	if err != nil {
		return spec, err
	}
	if from != nil {
		// A copy inherits its source's definition; only rotation mode and
		// expiry may be overridden here.
		if cmd.Flags().Changed("template") || cmd.Flags().Changed("param") {
			return spec, core.NewValidationError("--from-key", "cannot be combined with --template or --param; a copied key keeps its source's template (change it afterwards with `key edit`)")
		}
		if cmd.Flags().Changed("generator") || cmd.Flags().Changed("bytes") {
			return spec, core.NewValidationError("--from-key", "cannot be combined with --generator or --bytes; a copied key keeps its source's generator (change it afterwards with `key edit`)")
		}
		spec.CopyFrom, spec.Mode = from, kc.rotation
		if cmd.Flags().Changed("expires") {
			if spec.ExpiresAt, err = parseExpiry(kc.expires); err != nil {
				return spec, err
			}
			spec.ClearExpiry = spec.ExpiresAt == ""
		}
		return spec, nil
	}
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
	// A generated key needs a generator for its rotations; --generate needs
	// one for the first value whatever the mode (ops records it only for a
	// generated key).
	if rotation == core.RotationGenerated || value.generate {
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
	v, _, err := value.resolve(io, app.Stdin, spec.Generator, ui.Spec{Flag: ops.ValueFlagNames, Title: "Value for " + keyName})
	if err != nil {
		return spec, err
	}
	// An explicit value with a generated mode keeps the chosen generator
	// for future rotations; ops generates the initial value when Value is nil.
	spec.Value = v
	if kc.expires != "" {
		exp, err := parseExpiry(kc.expires)
		if err != nil {
			return spec, err
		}
		spec.ExpiresAt = exp
	}
	return spec, nil
}

func viewKeys(v *ops.SecretView) []ops.KeyView {
	if v == nil {
		return nil
	}
	return v.Keys
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
key with a generator, from --from-key, or from a masked prompt on a
terminal.

--from-key <secret>/<key> copies another registered key's current value
(for computed keys, its {{secret}} part; both keys must be the same kind)
and records the copy, which is how a copy follows its rotated source:

  waxseal key set support-cannon-ghcr .dockerconfigjson \
    --from-key default-ghcr/.dockerconfigjson

A key that was a copy stops being one when its value is set any other way.
When other keys are copies of this one, Next lists the command that
re-copies each.`,
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
		in := ops.SetKeyValueInput{ShortName: secretName, Key: keyName, DryRun: app.Flags.DryRun}
		if in.CopyFrom, err = value.copyRef(); err != nil {
			return nil, err
		}
		if in.CopyFrom == nil {
			var gen *core.GeneratorConfig
			if key.Generator != "" {
				gen = &core.GeneratorConfig{Kind: key.Generator}
			}
			v, gen, err := value.resolve(io, app.Stdin, gen, ui.Spec{Flag: ops.ValueFlagNames, Title: "New value for " + keyName})
			if err != nil {
				return nil, err
			}
			if gen != nil {
				if v, err = core.GenerateValue(gen); err != nil {
					return nil, err
				}
			}
			in.Value = v
		}
		// A key that expires needs a new expiry with its new value; a copy
		// takes its source's expiry when the source has one.
		needExpiry := key.ExpiresAt != "" || cmd.Flags().Changed("expires")
		if in.CopyFrom != nil && !cmd.Flags().Changed("expires") {
			// When the source can't be read, ops reports why; don't ask
			// for an expiry first.
			src, _ := svc.Show(in.CopyFrom.ShortName)
			found := false
			for _, k := range viewKeys(src) {
				if k.Name == in.CopyFrom.KeyName {
					found = true
					needExpiry = needExpiry && k.ExpiresAt == ""
				}
			}
			needExpiry = needExpiry && found
		}
		if needExpiry {
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
		summary := fmt.Sprintf("%s/%s set to GSM version %s", secretName, keyName, res.Versions[keyName])
		if in.CopyFrom != nil {
			summary = fmt.Sprintf("%s/%s copied from %s/%s as GSM version %s", secretName, keyName, in.CopyFrom.ShortName, in.CopyFrom.KeyName, res.Versions[keyName])
		}
		return mutation(app, res, summary, commitNext(res)...), nil
	})
	value.register(cmd)
	cmd.Flags().StringVar(&expires, "expires", "", "new expiry date (YYYY-MM-DD or RFC 3339), or 'none' to clear")
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
