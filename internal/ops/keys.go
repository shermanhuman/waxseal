package ops

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/computed"
	"github.com/shermanhuman/waxseal/internal/core"
)

// KeySpec describes a key to add. Exactly one of Value, Generator or
// CopyFrom supplies the secret; Template makes it a computed key whose
// {{secret}} is that value. CopyFrom copies another registered key's stored
// value and definition instead, and cannot be combined with Template.
type KeySpec struct {
	Name      string
	Value     []byte
	Generator *core.GeneratorConfig
	CopyFrom  *core.KeyRef
	Template  *TemplateSpec
	// Mode is the rotation mode; it defaults to generated with a Generator,
	// to the source's mode with CopyFrom, and to external otherwise. With
	// any mode but generated, a Generator only makes the first value and is
	// not recorded.
	Mode      string
	ExpiresAt string // RFC3339, optional
	// ClearExpiry drops an expiry a copy would inherit (--expires none).
	ClearExpiry bool
}

// TemplateSpec describes a computed key's template and its non-secret values.
type TemplateSpec struct {
	Template string
	Values   map[string]string
}

// build turns the spec into metadata plus what to store and seal. It is the
// one place that knows how a plain key and a computed key differ.
func (k KeySpec) build(resource string) (core.KeyMetadata, keyWrite, error) {
	if k.Name == "" {
		return core.KeyMetadata{}, keyWrite{}, &core.MissingInputError{Field: "<key>"}
	}
	if k.CopyFrom != nil {
		return core.KeyMetadata{}, keyWrite{}, errors.New("a copied key is built from its source, not by build")
	}
	if k.Value == nil && k.Generator == nil {
		return core.KeyMetadata{}, keyWrite{}, &core.MissingInputError{Field: ValueFlagNames}
	}
	// A Value given with a Generator is the first value; the generator is
	// kept for future rotations.
	value := k.Value
	if value == nil {
		var err error
		if value, err = core.GenerateValue(k.Generator); err != nil {
			return core.KeyMetadata{}, keyWrite{}, err
		}
	}
	mode := k.Mode
	if mode == "" {
		mode = core.RotationExternal
		if k.Generator != nil {
			mode = core.RotationGenerated
		}
	}
	// A generator is recorded only for a generated key: anything else would
	// invite `key set --generate` to replace a value meant to be kept.
	gen := k.Generator
	if mode != core.RotationGenerated {
		gen = nil
	}
	meta := core.KeyMetadata{
		KeyName:  k.Name,
		Rotation: &core.RotationConfig{Mode: mode, Generator: gen},
	}
	if k.ExpiresAt != "" {
		meta.Expiry = &core.ExpiryConfig{ExpiresAt: k.ExpiresAt}
	}
	ref := &core.GSMRef{SecretResource: resource}

	if k.Template == nil {
		meta.Source = core.SourceConfig{Kind: "gsm"}
		meta.GSM = ref
		return meta, keyWrite{name: k.Name, ref: ref, gsm: value, seal: value}, nil
	}

	payload, err := computed.NewPayload(k.Template.Template, k.Template.Values, string(value), gen)
	if err != nil {
		return core.KeyMetadata{}, keyWrite{}, core.WrapValidation("template", err)
	}
	if err := payload.Validate(); err != nil {
		return core.KeyMetadata{}, keyWrite{}, core.WrapValidation("template", err)
	}
	data, err := payload.Marshal()
	if err != nil {
		return core.KeyMetadata{}, keyWrite{}, err
	}
	meta.Source = core.SourceConfig{Kind: "computed"}
	meta.Computed = &core.ComputedConfig{Kind: "template", Template: k.Template.Template, GSM: ref}
	return meta, keyWrite{name: k.Name, ref: ref, gsm: data, seal: []byte(payload.Computed)}, nil
}

// ValueFlagNames names the inputs that can supply a key's value, for
// errors and prompts.
const ValueFlagNames = "--from-file, --generate or --from-key"

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// NewSecret describes a secret to create when AddKey targets one that is
// not registered yet.
type NewSecret struct {
	Namespace    string
	Name         string // defaults to the short name
	ManifestPath string // defaults to apps/<short>/sealed-secret.yaml
	Scope        string // defaults to strict
	Type         string // defaults to Opaque
}

// AddKeyInput adds a key to a secret, creating the secret when New is set.
type AddKeyInput struct {
	ShortName string
	Key       KeySpec
	New       *NewSecret
	DryRun    bool
}

// ErrKeyExists is wrapped when adding a key that is already present.
var ErrKeyExists = errors.New("key already exists")

// ErrNeedsNamespace is returned when AddKey targets an unregistered secret
// and no NewSecret was given; the CLI turns it into a prompt.
var ErrNeedsNamespace = errors.New("secret is not registered; a namespace is needed to create it")

// AddKey stores a new key's value in GSM, records it in metadata and seals
// it into the manifest.
func (s *Service) AddKey(ctx context.Context, in AddKeyInput) (*MutationResult, error) {
	var src *copySource
	if in.Key.CopyFrom != nil {
		if in.Key.Value != nil || in.Key.Generator != nil {
			return nil, core.NewValidationError("value", "give exactly one of "+ValueFlagNames)
		}
		if in.Key.Template != nil {
			return nil, core.NewValidationError("--from-key", "a copied key keeps its source's template; change it afterwards with `key edit`")
		}
		var err error
		if src, err = s.copySource(ctx, *in.Key.CopyFrom); err != nil {
			return nil, err
		}
	}
	m, err := s.activeMetadata(in.ShortName)
	switch {
	case errors.Is(err, ErrNotRegistered):
		if in.New == nil {
			return nil, fmt.Errorf("%s: %w", in.ShortName, ErrNeedsNamespace)
		}
		if in.New.Namespace == "" {
			return nil, &core.MissingInputError{Field: "--namespace"}
		}
		m = &core.SecretMetadata{
			ShortName:    in.ShortName,
			ManifestPath: cmp.Or(in.New.ManifestPath, "apps/"+in.ShortName+"/sealed-secret.yaml"),
			SealedSecret: core.SealedSecretRef{
				Name:      cmp.Or(in.New.Name, in.ShortName),
				Namespace: in.New.Namespace,
				Scope:     cmp.Or(in.New.Scope, core.ScopeStrict),
				Type:      in.New.Type,
			},
			Status: "active",
		}
		if src != nil && m.SealedSecret.Type == "" {
			// A copied .dockerconfigjson is useless in an Opaque secret.
			m.SealedSecret.Type = src.secret.SealedSecret.Type
		}
	case err != nil:
		return nil, err
	}
	if m.Key(in.Key.Name) != nil {
		return nil, fmt.Errorf("%s/%s: %w", m.ShortName, in.Key.Name, ErrKeyExists)
	}
	var meta core.KeyMetadata
	var write keyWrite
	if src != nil {
		if in.Key.Name == "" {
			return nil, &core.MissingInputError{Field: "<key>"}
		}
		meta, write, err = src.newKey(in.Key, m.ShortName, s.gsmResource(m.ShortName, in.Key.Name))
	} else {
		meta, write, err = in.Key.build(s.gsmResource(m.ShortName, in.Key.Name))
	}
	if err != nil {
		return nil, err
	}
	m.Keys = append(m.Keys, meta)
	write.ref = m.Keys[len(m.Keys)-1].ActiveRef()
	return s.apply(ctx, m, []keyWrite{write}, false, in.DryRun)
}

// SetKeyValueInput supplies a new value for an existing key.
type SetKeyValueInput struct {
	ShortName string
	Key       string
	Value     []byte
	// Generate produces the value with the key's own generator instead.
	Generate bool
	// CopyFrom copies another registered key's current value instead (for
	// a computed key, its {{secret}}), and records the copy. Without it,
	// a key that was a copy stops being one.
	CopyFrom *core.KeyRef
	// ExpiresAt: nil leaves expiry alone; "" clears it; otherwise RFC3339.
	ExpiresAt *string
	DryRun    bool
}

// SetKeyValue stores a new version of a key's value and re-seals it. For a
// computed key the value is the {{secret}} part of its computed.
func (s *Service) SetKeyValue(ctx context.Context, in SetKeyValueInput) (*MutationResult, error) {
	m, k, err := s.activeKey(in.ShortName, in.Key)
	if err != nil {
		return nil, err
	}
	if btoi(len(in.Value) > 0)+btoi(in.Generate)+btoi(in.CopyFrom != nil) > 1 {
		return nil, core.NewValidationError("value", "give exactly one of "+ValueFlagNames)
	}
	var src *copySource
	if in.CopyFrom != nil {
		if in.CopyFrom.ShortName == m.ShortName && in.CopyFrom.KeyName == k.KeyName {
			return nil, core.NewValidationError("--from-key", "a key cannot be copied from itself")
		}
		if src, err = s.copySource(ctx, *in.CopyFrom); err != nil {
			return nil, err
		}
		if in.Value, err = src.valueFor(k, m.ShortName+"/"+k.KeyName); err != nil {
			return nil, err
		}
	}
	if in.Generate {
		if k.Rotation == nil || k.Rotation.Generator == nil {
			return nil, &core.MissingInputError{Field: "--generator (the key has none; set one with `key edit`)"}
		}
		if in.Value, err = core.GenerateValue(k.Rotation.Generator); err != nil {
			return nil, err
		}
	}
	if len(in.Value) == 0 {
		return nil, &core.MissingInputError{Field: ValueFlagNames}
	}
	write, err := s.valueWrite(ctx, k, in.Value)
	if err != nil {
		return nil, err
	}
	var detached []CopyRef
	if src != nil {
		k.CopiedFrom = src.provenance()
		write.source = k.CopiedFrom.String()
		if in.ExpiresAt == nil && src.key.Expiry != nil {
			// The same credential expires when its source does.
			exp := *src.key.Expiry
			k.Expiry = &exp
		}
	} else {
		detached = detach(m.ShortName, k)
	}
	if in.ExpiresAt != nil {
		if *in.ExpiresAt == "" {
			k.Expiry = nil
		} else {
			k.Expiry = &core.ExpiryConfig{ExpiresAt: *in.ExpiresAt}
		}
	}
	res, err := s.apply(ctx, m, []keyWrite{write}, false, in.DryRun)
	if err != nil {
		return nil, err
	}
	res.Detached = detached
	res.Copies = s.copiesOf(m.ShortName, k.KeyName)
	return res, nil
}

// valueWrite prepares storing value as the key's new plaintext (plain key)
// or as the {{secret}} of its payload (computed key).
func (s *Service) valueWrite(ctx context.Context, k *core.KeyMetadata, value []byte) (keyWrite, error) {
	ref := k.ActiveRef()
	if ref == nil {
		return keyWrite{}, core.NewValidationError("key", k.KeyName+" has no GSM reference; its value is derived from other keys")
	}
	if k.Source.Kind != "computed" {
		return keyWrite{name: k.KeyName, ref: ref, gsm: value, seal: value}, nil
	}
	p, err := s.payload(ctx, k)
	if err != nil {
		return keyWrite{}, err
	}
	if err := p.UpdateSecret(string(value)); err != nil {
		return keyWrite{}, err
	}
	data, err := p.Marshal()
	if err != nil {
		return keyWrite{}, err
	}
	return keyWrite{name: k.KeyName, ref: ref, gsm: data, seal: []byte(p.Computed)}, nil
}

func (s *Service) payload(ctx context.Context, k *core.KeyMetadata) (*computed.Payload, error) {
	ref := k.Computed.GSM
	data, err := s.Store.AccessVersion(ctx, ref.SecretResource, ref.Version)
	if err != nil {
		return nil, fmt.Errorf("fetch payload for %s: %w", k.KeyName, err)
	}
	p, err := computed.ParsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("payload for %s: %w", k.KeyName, err)
	}
	return p, nil
}

// ErrKeyNotFound is wrapped when a key is not part of the secret.
var ErrKeyNotFound = errors.New("key not found")

func (s *Service) activeKey(shortName, key string) (*core.SecretMetadata, *core.KeyMetadata, error) {
	m, err := s.activeMetadata(shortName)
	if err != nil {
		return nil, nil, err
	}
	if key == "" {
		return nil, nil, &core.MissingInputError{Field: "<key>"}
	}
	k := m.Key(key)
	if k == nil {
		return nil, nil, fmt.Errorf("%s/%s: %w", shortName, key, ErrKeyNotFound)
	}
	return m, k, nil
}
