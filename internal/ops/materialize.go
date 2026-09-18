package ops

import (
	"context"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/template"
)

// materialize fetches every key's plaintext: GSM values, then computed
// keys rendered from their GSM payload or from sibling keys and params.
func (s *Service) materialize(ctx context.Context, m *core.SecretMetadata) (map[string][]byte, error) {
	values := map[string][]byte{}
	for i := range m.Keys {
		k := &m.Keys[i]
		if k.Source.Kind != "gsm" || k.GSM == nil {
			continue
		}
		v, err := s.Store.AccessVersion(ctx, k.GSM.SecretResource, k.GSM.Version)
		if err != nil {
			return nil, fmt.Errorf("fetch %s/%s: %w", m.ShortName, k.KeyName, err)
		}
		values[k.KeyName] = v
	}
	for i := range m.Keys {
		k := &m.Keys[i]
		if k.Source.Kind != "computed" || k.Computed == nil {
			continue
		}
		v, err := s.computeKey(ctx, m, k, values)
		if err != nil {
			return nil, fmt.Errorf("compute %s/%s: %w", m.ShortName, k.KeyName, err)
		}
		values[k.KeyName] = v
	}
	return values, nil
}

// computeKey renders one computed key. A key with a GSM payload is rendered
// from it; otherwise the template is filled from params and from sibling
// keys named by inputs.
func (s *Service) computeKey(ctx context.Context, m *core.SecretMetadata, k *core.KeyMetadata, siblings map[string][]byte) ([]byte, error) {
	c := k.Computed
	if c.GSM != nil {
		data, err := s.Store.AccessVersion(ctx, c.GSM.SecretResource, c.GSM.Version)
		if err != nil {
			return nil, err
		}
		p, err := template.ParsePayload(data)
		if err != nil {
			return nil, err
		}
		out, err := p.Compute()
		if err != nil {
			return nil, err
		}
		return []byte(out), nil
	}

	tmpl, err := template.Parse(c.Template)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for name, v := range c.Params {
		vars[name] = v
	}
	for _, in := range c.Inputs {
		if in.Ref.ShortName != "" && in.Ref.ShortName != m.ShortName {
			return nil, core.NewValidationError("computed.inputs", fmt.Sprintf(
				"input %q refers to secret %q; inputs can only refer to keys of the same secret", in.Var, in.Ref.ShortName))
		}
		v, ok := siblings[in.Ref.KeyName]
		if !ok {
			return nil, core.NewValidationError("computed.inputs", fmt.Sprintf("input %q refers to unknown key %q", in.Var, in.Ref.KeyName))
		}
		vars[in.Var] = string(v)
	}
	if len(vars) == 0 && len(tmpl.Variables()) > 0 {
		return nil, core.NewValidationError("computed", "template has variables but no GSM payload, inputs or params; add computed.gsm pointing at the payload")
	}
	out, err := tmpl.Execute(vars)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}
