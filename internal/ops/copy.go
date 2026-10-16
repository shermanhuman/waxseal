package ops

import (
	"context"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/computed"
	"github.com/shermanhuman/waxseal/internal/core"
)

// CopyRef pairs a key with a copy of it: Source is the key whose value was
// copied, Target the key holding the copy.
type CopyRef struct {
	Source core.KeyRef `json:"source"`
	Target core.KeyRef `json:"target"`
}

// copySource is a registered key whose stored value is being copied: its
// metadata and the bytes of its pinned GSM version (a plain value, or a
// computed key's payload). The bytes never leave ops.
type copySource struct {
	secret *core.SecretMetadata
	key    *core.KeyMetadata
	data   []byte
}

// copySource loads the key that ref names, from a secret of any status, and
// reads its pinned GSM version. A dry run reads it too, so a missing
// version fails before the dry run reports success.
func (s *Service) copySource(ctx context.Context, ref core.KeyRef) (*copySource, error) {
	if ref.ShortName == "" || ref.KeyName == "" {
		return nil, &core.MissingInputError{Field: "--from-key"}
	}
	m, err := s.metadata(ref.ShortName)
	if err != nil {
		return nil, err
	}
	k := m.Key(ref.KeyName)
	if k == nil {
		return nil, fmt.Errorf("%s/%s: %w", ref.ShortName, ref.KeyName, ErrKeyNotFound)
	}
	gsm := k.ActiveRef()
	if gsm == nil {
		return nil, core.NewValidationError("--from-key", ref.ShortName+"/"+ref.KeyName+" is derived from other keys; it has no stored value to copy")
	}
	if s.Store == nil {
		return nil, errors.New("GSM access is required")
	}
	data, err := s.Store.AccessVersion(ctx, gsm.SecretResource, gsm.Version)
	if err != nil {
		return nil, fmt.Errorf("read %s/%s (GSM version %s): %w", ref.ShortName, ref.KeyName, gsm.Version, err)
	}
	return &copySource{secret: m, key: k, data: data}, nil
}

func (c *copySource) ref() core.KeyRef {
	return core.KeyRef{ShortName: c.secret.ShortName, KeyName: c.key.KeyName}
}

func (c *copySource) provenance() *core.CopiedFrom {
	return &core.CopiedFrom{ShortName: c.secret.ShortName, KeyName: c.key.KeyName, Version: c.key.ActiveRef().Version}
}

func (c *copySource) computed() bool { return c.key.Source.Kind == "computed" }

// newKey builds a key named spec.Name that carries the source key's
// definition (kind, template, rotation, expiry, operator hints) and its
// stored bytes verbatim (minus the payload's generator when the copy is not
// generated), under the target's own GSM resource. spec.Mode, spec.ExpiresAt
// and spec.ClearExpiry override the inherited values.
func (c *copySource) newKey(spec KeySpec, target, resource string) (core.KeyMetadata, keyWrite, error) {
	src := c.key
	meta := core.KeyMetadata{
		KeyName:       spec.Name,
		Source:        src.Source,
		OperatorHints: src.OperatorHints,
		CopiedFrom:    c.provenance(),
	}
	if src.Rotation != nil {
		rot := *src.Rotation
		if rot.Generator != nil {
			gen := *rot.Generator
			rot.Generator = &gen
		}
		meta.Rotation = &rot
	}
	if spec.Mode != "" {
		if meta.Rotation == nil {
			meta.Rotation = &core.RotationConfig{}
		}
		meta.Rotation.Mode = spec.Mode
	}
	if meta.Rotation != nil {
		switch {
		case meta.Rotation.Mode != core.RotationGenerated:
			// As in build: a generator is recorded only for a generated key.
			meta.Rotation.Generator = nil
		case meta.Rotation.Generator == nil:
			return core.KeyMetadata{}, keyWrite{}, core.NewValidationError("--rotation", fmt.Sprintf(
				"%s/%s has no generator; copy it first, then run `waxseal key edit %s %s --rotation generated --generator <kind>`",
				c.secret.ShortName, src.KeyName, target, spec.Name))
		}
	}
	switch {
	case spec.ClearExpiry:
	case spec.ExpiresAt != "":
		meta.Expiry = &core.ExpiryConfig{ExpiresAt: spec.ExpiresAt}
	case src.Expiry != nil:
		exp := *src.Expiry
		meta.Expiry = &exp
	}

	ref := &core.GSMRef{SecretResource: resource}
	w := keyWrite{name: spec.Name, ref: ref, gsm: c.data, source: c.provenance().String()}
	if !c.computed() {
		meta.GSM = ref
		w.seal = c.data
		return meta, w, nil
	}
	p, err := computed.ParsePayload(c.data)
	if err != nil {
		return core.KeyMetadata{}, keyWrite{}, fmt.Errorf("payload of %s/%s: %w", c.secret.ShortName, src.KeyName, err)
	}
	out, err := p.Compute()
	if err != nil {
		return core.KeyMetadata{}, keyWrite{}, fmt.Errorf("payload of %s/%s: %w", c.secret.ShortName, src.KeyName, err)
	}
	meta.Computed = &core.ComputedConfig{Kind: "template", Template: src.Computed.Template, GSM: ref}
	w.seal = []byte(out)
	if p.Generator != nil && (meta.Rotation == nil || meta.Rotation.Generator == nil) {
		// A copy that isn't generated records no generator in its payload
		// either; the rest of the payload is copied as is.
		p.Generator = nil
		if w.gsm, err = p.Marshal(); err != nil {
			return core.KeyMetadata{}, keyWrite{}, err
		}
	}
	return meta, w, nil
}

// valueFor returns what `key set` stores for target: the source's bytes
// for a plain key, or the source payload's {{secret}} for a computed key,
// whose own template and values stay. Mixed kinds are refused.
func (c *copySource) valueFor(target *core.KeyMetadata, targetName string) ([]byte, error) {
	targetComputed := target.Source.Kind == "computed"
	if targetComputed != c.computed() {
		kind := func(computed bool) string {
			if computed {
				return "a computed key"
			}
			return "a plain key"
		}
		return nil, core.NewValidationError("--from-key", fmt.Sprintf("%s is %s and %s is %s; copy between keys of the same kind",
			c.ref().ShortName+"/"+c.ref().KeyName, kind(c.computed()), targetName, kind(targetComputed)))
	}
	if !c.computed() {
		return c.data, nil
	}
	p, err := computed.ParsePayload(c.data)
	if err != nil {
		return nil, fmt.Errorf("payload of %s/%s: %w", c.secret.ShortName, c.key.KeyName, err)
	}
	return []byte(p.Secret), nil
}

// copiesOf lists the active keys recorded as copies of shortName/keyName.
func (s *Service) copiesOf(shortName, keyName string) []CopyRef {
	secrets, _ := s.Repo.AllMetadata()
	var out []CopyRef
	for _, m := range secrets {
		if m.IsRetired() {
			continue
		}
		for _, k := range m.Keys {
			if cf := k.CopiedFrom; cf != nil && cf.ShortName == shortName && cf.KeyName == keyName {
				out = append(out, CopyRef{
					Source: core.KeyRef{ShortName: shortName, KeyName: keyName},
					Target: core.KeyRef{ShortName: m.ShortName, KeyName: k.KeyName},
				})
			}
		}
	}
	return out
}

// detach clears a key's copy provenance because its value is changing
// some other way, and returns the pair it broke, if any.
func detach(shortName string, k *core.KeyMetadata) []CopyRef {
	if k.CopiedFrom == nil {
		return nil
	}
	ref := CopyRef{
		Source: core.KeyRef{ShortName: k.CopiedFrom.ShortName, KeyName: k.CopiedFrom.KeyName},
		Target: core.KeyRef{ShortName: shortName, KeyName: k.KeyName},
	}
	k.CopiedFrom = nil
	return []CopyRef{ref}
}
