package ops

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/template"
)

// ImportInput registers a manifest by reading its plaintext from the
// cluster. ShortName is either a suggested name from Discover (for a new
// manifest) or an existing secret to re-import.
type ImportInput struct {
	ShortName string
	DryRun    bool
}

// ImportResult reports an import.
type ImportResult struct {
	*MutationResult
	Added            []string `json:"added"`            // keys registered from the cluster
	Updated          []string `json:"updated"`          // keys already registered, re-pushed
	MissingInCluster []string `json:"missingInCluster"` // keys in metadata the cluster no longer has
	Templated        []string `json:"templated,omitempty"`
}

// Import pushes a cluster secret's values to GSM and writes metadata for
// it. Connection strings become computed keys with the password as their
// {{secret}}. Every key is registered as externally rotated; adjust with
// EditKey.
func (s *Service) Import(ctx context.Context, in ImportInput) (*ImportResult, error) {
	if s.Cluster == nil {
		return nil, errors.New("import needs kubectl access to the cluster")
	}
	m, err := s.metadata(in.ShortName)
	if errors.Is(err, ErrNotRegistered) {
		m, err = s.metadataForManifest(in.ShortName)
	}
	if err != nil {
		return nil, err
	}
	if m.IsRetired() {
		return nil, fmt.Errorf("%s: %w", m.ShortName, core.ErrRetired)
	}

	data, err := s.Cluster.GetSecret(ctx, m.SealedSecret.Namespace, m.SealedSecret.Name)
	if err != nil {
		return nil, fmt.Errorf("read %s/%s from the cluster: %w", m.SealedSecret.Namespace, m.SealedSecret.Name, err)
	}
	res := &ImportResult{}
	res.MissingInCluster, _ = diffKeys(m, data)

	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	slices.Sort(names)

	var writes []keyWrite
	for _, name := range names {
		value := data[name]
		k := m.Key(name)
		if k == nil {
			m.Keys = append(m.Keys, core.KeyMetadata{KeyName: name, Rotation: &core.RotationConfig{Mode: core.RotationExternal}})
			k = &m.Keys[len(m.Keys)-1]
			res.Added = append(res.Added, name)
		} else {
			res.Updated = append(res.Updated, name)
		}
		resource := s.gsmResource(m.ShortName, name)
		if ref := k.ActiveRef(); ref != nil {
			resource = ref.SecretResource
		}
		ref := &core.GSMRef{SecretResource: resource}

		if tmpl, values, secret, ok := detectTemplate(string(value)); ok && (k.Source.Kind == "computed" || k.Source.Kind == "") {
			payload, err := template.NewPayload(tmpl, values, secret, nil)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			pdata, err := payload.Marshal()
			if err != nil {
				return nil, err
			}
			k.Source = core.SourceConfig{Kind: "computed"}
			k.GSM = nil
			k.Computed = &core.ComputedConfig{Kind: "template", Template: tmpl, GSM: ref}
			writes = append(writes, keyWrite{name: name, ref: ref, gsm: pdata, seal: []byte(payload.Computed)})
			res.Templated = append(res.Templated, name)
			continue
		}
		k.Source = core.SourceConfig{Kind: "gsm"}
		k.Computed = nil
		k.GSM = ref
		writes = append(writes, keyWrite{name: name, ref: ref, gsm: value, seal: value})
	}

	res.MutationResult, err = s.apply(ctx, m, writes, false, in.DryRun)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// metadataForManifest builds fresh metadata for a discovered manifest whose
// suggested short name is name.
func (s *Service) metadataForManifest(name string) (*core.SecretMetadata, error) {
	found, err := s.Discover()
	if err != nil {
		return nil, err
	}
	for _, d := range found {
		if d.Suggested != name || d.Registered != "" {
			continue
		}
		return &core.SecretMetadata{
			ShortName:    name,
			ManifestPath: d.Path,
			SealedSecret: core.SealedSecretRef{Name: d.Name, Namespace: d.Namespace, Scope: d.Scope, Type: typeOrEmpty(d.Type)},
			Status:       "active",
		}, nil
	}
	return nil, fmt.Errorf("%s: %w; run `waxseal discover` for the names it suggests", name, ErrNotRegistered)
}

func typeOrEmpty(t string) string {
	if t == "Opaque" {
		return ""
	}
	return t
}

// detectTemplate recognises a connection string and splits it into a
// template, its non-secret values and the password.
func detectTemplate(value string) (tmpl string, values map[string]string, secret string, ok bool) {
	ok, tmpl, values = template.DetectConnectionString(value, nil)
	if !ok {
		return "", nil, "", false
	}
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return "", nil, "", false
	}
	secret, hasPassword := u.User.Password()
	if !hasPassword || secret == "" {
		return "", nil, "", false
	}
	return tmpl, values, secret, true
}
