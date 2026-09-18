package ops

import "strings"

// Discovered is a SealedSecret manifest found in the repository and whether
// metadata already covers it.
type Discovered struct {
	Path      string   `json:"path"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Type      string   `json:"type"`
	Keys      []string `json:"keys"`
	// Registered is the short name of the metadata covering this manifest,
	// or "" when it is new. Suggested is the short name import would use.
	Registered string `json:"registered,omitempty"`
	Suggested  string `json:"suggested"`
}

// Discover lists SealedSecret manifests in the repository. It writes
// nothing: registering needs the plaintext, which `import` reads from the
// cluster.
func (s *Service) Discover() ([]Discovered, error) {
	found, err := s.Repo.FindManifests()
	if err != nil {
		return nil, err
	}
	secrets, _ := s.Repo.AllMetadata()
	byPath := map[string]string{}
	byName := map[string]string{}
	for _, m := range secrets {
		byPath[m.ManifestPath] = m.ShortName
		byName[m.SealedSecret.Namespace+"/"+m.SealedSecret.Name] = m.ShortName
	}

	out := make([]Discovered, 0, len(found))
	for _, f := range found {
		ss := f.Secret
		d := Discovered{
			Path:      f.Path,
			Namespace: ss.Metadata.Namespace,
			Name:      ss.Metadata.Name,
			Scope:     ss.GetScope(),
			Type:      ss.GetSecretType(),
			Keys:      ss.GetEncryptedKeys(),
			Suggested: DeriveShortName(ss.Metadata.Namespace, ss.Metadata.Name),
		}
		if short, ok := byPath[f.Path]; ok {
			d.Registered = short
		} else if short, ok := byName[ss.Metadata.Namespace+"/"+ss.Metadata.Name]; ok {
			d.Registered = short
		}
		out = append(out, d)
	}
	return out, nil
}

// DeriveShortName proposes a short name for a manifest: namespace-name,
// made safe for use as a file name.
func DeriveShortName(namespace, name string) string {
	short := namespace + "-" + name
	return strings.NewReplacer("/", "-", "\\", "-").Replace(short)
}
