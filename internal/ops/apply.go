package ops

import (
	"context"
	"errors"
	"fmt"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/seal"
	"github.com/shermanhuman/waxseal/internal/store"
)

// keyWrite is one key's part of a mutation: what to store in GSM and what
// to seal into the manifest. Either may be nil.
type keyWrite struct {
	name string
	ref  *core.GSMRef // where the new GSM version is recorded; resource must be set
	gsm  []byte       // bytes for a new GSM version, or nil
	seal []byte       // plaintext to seal, or nil to leave the ciphertext alone
}

// MutationResult is what every secret mutation returns.
type MutationResult struct {
	ShortName string            `json:"shortName"`
	DryRun    bool              `json:"dryRun"`
	Changes   []Change          `json:"changes"`
	Versions  map[string]string `json:"versions,omitempty"` // key -> new GSM version
}

// UnrecordedVersionError is returned when GSM versions were created but the
// metadata that points to them could not be written. The versions are
// listed so the user can record them by hand; re-running is also safe.
type UnrecordedVersionError struct {
	Versions map[string]string // resource -> version
	Err      error
}

func (e *UnrecordedVersionError) Error() string {
	return fmt.Sprintf("GSM versions were created but metadata was not updated (%v): %v", e.Versions, e.Err)
}

func (e *UnrecordedVersionError) Unwrap() error { return e.Err }

// apply is the one transaction behind every secret mutation:
//
//  1. Seal in memory first, so kubeseal and certificate problems surface
//     before anything is written anywhere.
//  2. In a dry run, stop here and report the planned changes.
//  3. Write GSM versions, remembering which secrets this call created.
//  4. Commit metadata then manifest (repo.Commit orders the renames).
//  5. On failure after 3: delete only the secrets this call created; a
//     version added to a pre-existing secret is inert and is reported.
//
// replaceAll re-seals every key from sealed (a full reseal); otherwise the
// sealed keys are merged into the existing manifest.
func (s *Service) apply(ctx context.Context, m *core.SecretMetadata, writes []keyWrite, replaceAll, dryRun bool) (*MutationResult, error) {
	// Validate up front. New keys have no GSM version yet; stand in a
	// placeholder so the rest of the metadata is checked before any work.
	var pending []*core.GSMRef
	for _, w := range writes {
		if w.gsm != nil && w.ref.Version == "" {
			w.ref.Version = "1"
			pending = append(pending, w.ref)
		}
	}
	err := m.Validate()
	for _, ref := range pending {
		ref.Version = ""
	}
	if err != nil {
		return nil, err
	}
	res := &MutationResult{ShortName: m.ShortName, DryRun: dryRun, Versions: map[string]string{}}

	// 1. Seal in memory.
	sealed := map[string]string{}
	if len(writes) > 0 && s.Sealer == nil {
		return nil, errors.New("sealing requires kubeseal and the controller certificate")
	}
	for _, w := range writes {
		if w.seal == nil {
			continue
		}
		enc, err := s.Sealer.Seal(m.SealedSecret.Name, m.SealedSecret.Namespace, w.name, w.seal, m.SealedSecret.Scope)
		if err != nil {
			return nil, fmt.Errorf("seal %s/%s: %w", m.ShortName, w.name, err)
		}
		sealed[w.name] = enc
	}

	existing, err := s.Repo.Manifest(m)
	if err != nil && !core.IsNotFound(err) {
		return nil, err
	}
	for _, w := range writes {
		if w.gsm != nil {
			res.Changes = append(res.Changes, Change{Op: "create", Kind: "gsm-version", Target: w.ref.SecretResource})
		}
	}
	res.Changes = append(res.Changes, Change{Op: "update", Kind: "metadata", Target: s.Repo.MetadataPath(m.ShortName)})
	manifestOp := "update"
	if existing == nil {
		manifestOp = "create"
	}
	res.Changes = append(res.Changes, Change{Op: manifestOp, Kind: "manifest", Target: m.ManifestPath})

	// 2. Dry run stops before the first side effect.
	if dryRun {
		return res, nil
	}

	// 3. GSM writes.
	if s.Store == nil {
		return nil, errors.New("GSM access is required")
	}
	var created []string
	undo := func() {
		for _, resource := range created {
			_ = s.Store.DeleteSecret(ctx, resource)
		}
	}
	unrecorded := map[string]string{}
	for _, w := range writes {
		if w.gsm == nil {
			continue
		}
		version, wasCreated, err := s.Store.EnsureVersion(ctx, w.ref.SecretResource, w.gsm)
		if err != nil {
			undo()
			return nil, fmt.Errorf("store %s/%s in GSM: %w", m.ShortName, w.name, err)
		}
		if wasCreated {
			created = append(created, w.ref.SecretResource)
		} else {
			unrecorded[w.ref.SecretResource] = version
		}
		w.ref.Version = version
		res.Versions[w.name] = version
	}

	// 4. Metadata then manifest.
	ss := buildManifest(m, existing, sealed, replaceAll)
	if err := s.Repo.Commit(m, ss); err != nil {
		undo()
		if len(unrecorded) > 0 {
			return nil, &UnrecordedVersionError{Versions: unrecorded, Err: err}
		}
		return nil, err
	}
	return res, nil
}

// buildManifest produces the manifest to write: name, namespace, scope
// annotations and type always come from metadata; user-added labels and
// annotations on the existing manifest are kept.
func buildManifest(m *core.SecretMetadata, existing *seal.SealedSecret, sealed map[string]string, replaceAll bool) *seal.SealedSecret {
	data := map[string]string{}
	if existing != nil && !replaceAll {
		for k, v := range existing.Spec.EncryptedData {
			data[k] = v
		}
	}
	for k, v := range sealed {
		data[k] = v
	}
	ss := seal.NewSealedSecret(m.SealedSecret.Name, m.SealedSecret.Namespace, m.SealedSecret.Scope, m.SealedSecret.Type, data)
	if existing != nil {
		for k, v := range existing.Metadata.Annotations {
			if _, scopeAnnotation := ss.Metadata.Annotations[k]; !scopeAnnotation && !isScopeAnnotation(k) {
				if ss.Metadata.Annotations == nil {
					ss.Metadata.Annotations = map[string]string{}
				}
				ss.Metadata.Annotations[k] = v
			}
		}
		if len(existing.Metadata.Labels) > 0 {
			ss.Metadata.Labels = existing.Metadata.Labels
		}
		if existing.Spec.Template != nil && existing.Spec.Template.Metadata != nil {
			if ss.Spec.Template == nil {
				ss.Spec.Template = &seal.SecretTemplateSpec{}
			}
			ss.Spec.Template.Metadata = existing.Spec.Template.Metadata
		}
	}
	return ss
}

func isScopeAnnotation(k string) bool {
	switch k {
	case seal.AnnotationScope, "sealedsecrets.bitnami.com/namespace-wide", "sealedsecrets.bitnami.com/cluster-wide":
		return true
	}
	return false
}

// gsmResource names the GSM secret that holds a key's value.
func (s *Service) gsmResource(shortName, keyName string) string {
	return store.SecretResource(s.ProjectID, store.FormatSecretID(shortName, keyName))
}
