package ops

import (
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/repo"
)

// RetireInput describes a retirement.
type RetireInput struct {
	ShortName      string
	Reason         string
	ReplacedBy     string
	DeleteManifest bool
	DryRun         bool
}

// Retire marks a secret retired. Its GSM secrets are left in place; its
// manifest is deleted only when asked.
func (s *Service) Retire(in RetireInput) (*MutationResult, error) {
	m, err := s.metadata(in.ShortName)
	if err != nil {
		return nil, err
	}
	res := &MutationResult{ShortName: m.ShortName, DryRun: in.DryRun}
	if !m.IsRetired() {
		m.Status = "retired"
		m.RetiredAt = s.now().UTC().Format(time.RFC3339)
		m.RetireReason = in.Reason
		m.ReplacedBy = in.ReplacedBy
		res.Changes = append(res.Changes, Change{Op: "update", Kind: "metadata", Target: repo.MetadataRel(m.ShortName)})
	}
	if in.DeleteManifest {
		if _, err := s.Repo.Manifest(m); err == nil {
			res.Changes = append(res.Changes, Change{Op: "delete", Kind: "manifest", Target: m.ManifestPath})
		} else if !core.IsNotFound(err) {
			return nil, err
		}
	}
	if in.DryRun || len(res.Changes) == 0 {
		return res, nil
	}
	if err := s.Repo.WriteMetadata(m); err != nil {
		return nil, err
	}
	if in.DeleteManifest {
		if err := s.Repo.DeleteManifest(m); err != nil {
			return nil, err
		}
	}
	return res, nil
}
