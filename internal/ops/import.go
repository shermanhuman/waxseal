package ops

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/shermanhuman/waxseal/internal/computed"
	"github.com/shermanhuman/waxseal/internal/core"
)

// ImportInput registers a manifest by reading its plaintext from the
// cluster. ShortName is either a suggested name from Discover (for a new
// manifest) or an existing secret to re-import. Discovered, if set, is a
// Discover result to look the name up in, saving a repository walk per
// import.
type ImportInput struct {
	ShortName  string
	Discovered []Discovered
	DryRun     bool
}

// ImportResult reports an import.
type ImportResult struct {
	*MutationResult
	Added            []string `json:"added"`            // keys registered from the cluster
	Updated          []string `json:"updated"`          // keys already registered, re-pushed
	MissingInCluster []string `json:"missingInCluster"` // keys in metadata the cluster no longer has
	Templated        []string `json:"templated,omitempty"`
	Skipped          []string `json:"skipped,omitempty"` // computed keys whose value cannot be re-imported
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
		m, err = s.metadataForManifest(in.ShortName, in.Discovered)
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
		isNew := k == nil
		if isNew {
			m.Keys = append(m.Keys, core.KeyMetadata{KeyName: name, Rotation: &core.RotationConfig{Mode: core.RotationExternal}})
			k = &m.Keys[len(m.Keys)-1]
		}
		tmpl, values, secret, isConn := computed.DetectConnectionString(string(value))

		switch {
		case isNew && isConn, k.Source.Kind == "computed" && isConn && k.Computed != nil && k.Computed.GSM != nil:
			// A new connection string becomes a computed key; an existing
			// computed key gets a new payload version on its own resource.
			ref := &core.GSMRef{SecretResource: s.gsmResource(m.ShortName, name)}
			if !isNew {
				ref.SecretResource = k.Computed.GSM.SecretResource
			}
			payload, err := computed.NewPayload(tmpl, values, secret, nil)
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
		case k.Source.Kind == "computed":
			// The cluster holds the rendered value; it cannot be split back
			// into template and secret. Leave the key alone.
			m.Keys = m.Keys[:len(m.Keys)]
			res.Skipped = append(res.Skipped, name)
			continue
		default:
			// A plain key keeps its resource; a new key gets one.
			ref := &core.GSMRef{SecretResource: s.gsmResource(m.ShortName, name)}
			if k.GSM != nil {
				ref.SecretResource = k.GSM.SecretResource
			}
			k.Source = core.SourceConfig{Kind: "gsm"}
			k.Computed = nil
			k.GSM = ref
			writes = append(writes, keyWrite{name: name, ref: ref, gsm: value, seal: value})
		}
		if isNew {
			res.Added = append(res.Added, name)
		} else {
			res.Updated = append(res.Updated, name)
		}
	}
	if len(writes) == 0 {
		res.MutationResult = &MutationResult{ShortName: m.ShortName, DryRun: in.DryRun}
		return res, nil
	}

	res.MutationResult, err = s.apply(ctx, m, writes, false, in.DryRun)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// metadataForManifest builds fresh metadata for a discovered manifest whose
// suggested short name is name.
func (s *Service) metadataForManifest(name string, found []Discovered) (*core.SecretMetadata, error) {
	if found == nil {
		var err error
		if found, err = s.Discover(); err != nil {
			return nil, err
		}
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
