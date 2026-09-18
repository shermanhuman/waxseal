package ops

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
)

// SecretSummary is one row of `secret list`.
type SecretSummary struct {
	ShortName     string   `json:"shortName"`
	Status        string   `json:"status"`
	Namespace     string   `json:"namespace"`
	Name          string   `json:"name"`
	KeyCount      int      `json:"keyCount"`
	RotationModes []string `json:"rotationModes"`
	// Expiry is "", "expired" or "expiring" (within warnDays).
	Expiry string `json:"expiry,omitempty"`
}

// List summarises every registered secret. Files that fail to load are
// returned as errors alongside the rows that did load.
func (s *Service) List(warnDays int) ([]SecretSummary, []error) {
	secrets, errs := s.Repo.AllMetadata()
	now := s.now()
	rows := make([]SecretSummary, 0, len(secrets))
	for _, m := range secrets {
		row := SecretSummary{
			ShortName: m.ShortName,
			Status:    status(m),
			Namespace: m.SealedSecret.Namespace,
			Name:      m.SealedSecret.Name,
			KeyCount:  len(m.Keys),
		}
		for _, k := range m.Keys {
			mode := rotationMode(&k)
			if !slices.Contains(row.RotationModes, mode) {
				row.RotationModes = append(row.RotationModes, mode)
			}
		}
		slices.Sort(row.RotationModes)
		switch {
		case m.ExpiresBefore(now):
			row.Expiry = "expired"
		case m.ExpiresBefore(now.AddDate(0, 0, warnDays)):
			row.Expiry = "expiring"
		}
		rows = append(rows, row)
	}
	return rows, errs
}

// KeyView is one key as shown by `secret show`.
type KeyView struct {
	Name         string `json:"name"`
	Source       string `json:"source"`
	RotationMode string `json:"rotationMode"`
	Generator    string `json:"generator,omitempty"`
	GSMResource  string `json:"gsmResource,omitempty"`
	GSMVersion   string `json:"gsmVersion,omitempty"`
	Template     string `json:"template,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	// DaysLeft is nil when the key has no expiry.
	DaysLeft *int `json:"daysLeft,omitempty"`
}

// SecretView is the detail of one secret.
type SecretView struct {
	ShortName    string    `json:"shortName"`
	Status       string    `json:"status"`
	RetiredAt    string    `json:"retiredAt,omitempty"`
	RetireReason string    `json:"retireReason,omitempty"`
	ReplacedBy   string    `json:"replacedBy,omitempty"`
	Namespace    string    `json:"namespace"`
	Name         string    `json:"name"`
	Scope        string    `json:"scope"`
	Type         string    `json:"type"`
	ManifestPath string    `json:"manifestPath"`
	Keys         []KeyView `json:"keys"`
}

// Show returns the detail of one secret, retired or not.
func (s *Service) Show(shortName string) (*SecretView, error) {
	m, err := s.metadata(shortName)
	if err != nil {
		return nil, err
	}
	v := &SecretView{
		ShortName:    m.ShortName,
		Status:       status(m),
		RetiredAt:    m.RetiredAt,
		RetireReason: m.RetireReason,
		ReplacedBy:   m.ReplacedBy,
		Namespace:    m.SealedSecret.Namespace,
		Name:         m.SealedSecret.Name,
		Scope:        m.SealedSecret.Scope,
		Type:         secretType(m),
		ManifestPath: m.ManifestPath,
	}
	now := s.now()
	for i := range m.Keys {
		k := &m.Keys[i]
		kv := KeyView{Name: k.KeyName, Source: k.Source.Kind, RotationMode: rotationMode(k)}
		if k.Rotation != nil && k.Rotation.Generator != nil {
			kv.Generator = k.Rotation.Generator.Kind
		}
		if ref := k.ActiveRef(); ref != nil {
			kv.GSMResource, kv.GSMVersion = ref.SecretResource, ref.Version
		}
		if k.Computed != nil {
			kv.Template = k.Computed.Template
		}
		if exp, ok := k.ExpiresAt(); ok {
			kv.ExpiresAt = k.Expiry.ExpiresAt
			days := daysBetween(now, exp)
			kv.DaysLeft = &days
		}
		v.Keys = append(v.Keys, kv)
	}
	return v, nil
}

// ActiveSecretNames returns the short names of every non-retired secret,
// for pickers and completion.
func (s *Service) ActiveSecretNames() []string {
	secrets, _ := s.Repo.AllMetadata()
	var names []string
	for _, m := range secrets {
		if !m.IsRetired() {
			names = append(names, m.ShortName)
		}
	}
	return names
}

func status(m *core.SecretMetadata) string {
	if m.Status == "" {
		return "active"
	}
	return m.Status
}

func secretType(m *core.SecretMetadata) string {
	if m.SealedSecret.Type == "" {
		return "Opaque"
	}
	return m.SealedSecret.Type
}

func rotationMode(k *core.KeyMetadata) string {
	if k.Rotation != nil && k.Rotation.Mode != "" {
		return k.Rotation.Mode
	}
	return core.RotationUnknown
}

func daysBetween(from, to time.Time) int {
	return int(to.Sub(from).Hours() / 24)
}

// ErrNotRegistered is wrapped when a short name is not a registered secret.
var ErrNotRegistered = errors.New("secret is not registered")

// metadata loads a secret by short name, mapping a missing file to
// ErrNotRegistered.
func (s *Service) metadata(shortName string) (*core.SecretMetadata, error) {
	if shortName == "" {
		return nil, &core.MissingInputError{Field: "<secret>"}
	}
	m, err := s.Repo.Metadata(shortName)
	if err != nil {
		if core.IsNotFound(err) {
			return nil, fmt.Errorf("%s: %w", shortName, ErrNotRegistered)
		}
		return nil, err
	}
	return m, nil
}

// activeMetadata is metadata for a secret that may still be changed.
func (s *Service) activeMetadata(shortName string) (*core.SecretMetadata, error) {
	m, err := s.metadata(shortName)
	if err != nil {
		return nil, err
	}
	if m.IsRetired() {
		return nil, fmt.Errorf("%s: %w", shortName, core.ErrRetired)
	}
	return m, nil
}
