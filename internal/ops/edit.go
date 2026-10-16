package ops

import (
	"context"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/repo"
)

// EditKeyInput changes how a key is managed, not its value.
type EditKeyInput struct {
	ShortName string
	Key       string
	Rotation  *string               // nil leaves it alone
	Generator *core.GeneratorConfig // nil leaves it alone
	ExpiresAt *string               // nil leaves it alone; "" clears
	DryRun    bool
}

// EditKey updates a key's rotation mode, generator or expiry in metadata.
func (s *Service) EditKey(in EditKeyInput) (*MutationResult, error) {
	m, k, err := s.activeKey(in.ShortName, in.Key)
	if err != nil {
		return nil, err
	}
	if in.Rotation == nil && in.Generator == nil && in.ExpiresAt == nil {
		return nil, &core.MissingInputError{Field: "--rotation, --generator or --expires"}
	}
	if k.Rotation == nil {
		k.Rotation = &core.RotationConfig{Mode: core.RotationUnknown}
	}
	if in.Rotation != nil {
		k.Rotation.Mode = *in.Rotation
	}
	if in.Generator != nil {
		k.Rotation.Generator = in.Generator
	}
	if k.Rotation.Mode == core.RotationGenerated && k.Rotation.Generator == nil {
		return nil, &core.MissingInputError{Field: "--generator"}
	}
	if in.ExpiresAt != nil {
		if *in.ExpiresAt == "" {
			k.Expiry = nil
		} else {
			k.Expiry = &core.ExpiryConfig{ExpiresAt: *in.ExpiresAt}
		}
	}
	res := &MutationResult{ShortName: m.ShortName, DryRun: in.DryRun, Changes: []Change{{Op: "update", Kind: "metadata", Target: repo.MetadataRel(m.ShortName)}}}
	if in.DryRun {
		return res, nil
	}
	if err := s.Repo.WriteMetadata(m); err != nil {
		return nil, err
	}
	return res, nil
}

// ComputedView describes a computed key without its secret.
type ComputedView struct {
	Template  string            `json:"template"`
	Values    map[string]string `json:"values"`
	Generated bool              `json:"generated"`
}

// DescribeComputed returns a computed key's template and non-secret values.
func (s *Service) DescribeComputed(ctx context.Context, shortName, key string) (*ComputedView, error) {
	_, k, err := s.activeKey(shortName, key)
	if err != nil {
		return nil, err
	}
	if k.Source.Kind != "computed" || k.Computed == nil || k.Computed.GSM == nil {
		return nil, core.NewValidationError("key", key+" is not a computed key with a GSM payload")
	}
	p, err := s.payload(ctx, k)
	if err != nil {
		return nil, err
	}
	return &ComputedView{Template: p.Template, Values: p.Values, Generated: p.Generator != nil}, nil
}

// UpdateComputedInput changes a computed key's template or values; the
// secret part is untouched.
type UpdateComputedInput struct {
	ShortName string
	Key       string
	Template  *string           // nil leaves it alone
	Values    map[string]string // merged into the payload's values
	DryRun    bool
}

// UpdateComputed stores a new payload version with the changed template or
// values and re-seals the rendered result.
func (s *Service) UpdateComputed(ctx context.Context, in UpdateComputedInput) (*MutationResult, error) {
	m, k, err := s.activeKey(in.ShortName, in.Key)
	if err != nil {
		return nil, err
	}
	if k.Source.Kind != "computed" || k.Computed == nil || k.Computed.GSM == nil {
		return nil, core.NewValidationError("key", in.Key+" is not a computed key with a GSM payload")
	}
	if in.Template == nil && len(in.Values) == 0 {
		return nil, &core.MissingInputError{Field: "--template or --param"}
	}
	p, err := s.payload(ctx, k)
	if err != nil {
		return nil, err
	}
	if in.Template != nil {
		if !strings.Contains(*in.Template, "{{secret}}") {
			return nil, core.NewValidationError("--template", "must contain {{secret}}")
		}
		p.Template = *in.Template
	}
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	for name, v := range in.Values {
		p.Values[name] = v
	}
	if err := p.Validate(); err != nil {
		return nil, core.WrapValidation("template", err)
	}
	if err := p.UpdateSecret(p.Secret); err != nil {
		return nil, err
	}
	data, err := p.Marshal()
	if err != nil {
		return nil, err
	}
	k.Computed.Template = p.Template
	write := keyWrite{name: k.KeyName, ref: k.Computed.GSM, gsm: data, seal: []byte(p.Computed)}
	res, err := s.apply(ctx, m, []keyWrite{write}, false, in.DryRun)
	if err != nil {
		return nil, err
	}
	// The payload has a new version, so copies are behind it; re-copying
	// realigns them (their {{secret}} is unchanged).
	res.Copies = s.copiesOf(m.ShortName, k.KeyName)
	return res, nil
}
