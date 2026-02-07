// Package state manages persistent state for waxseal operations.
// State is stored in .waxseal/state.yaml and tracks:
// - Last certificate fingerprint (for cert rotation detection)
// - Rotation audit trail
// - Retirement audit trail
package state

import (
	"os"
	"path/filepath"
	"time"

	"github.com/shermanhuman/waxseal/internal/files"
	"sigs.k8s.io/yaml"
)

// State represents the persistent state of waxseal operations.
// Stored in .waxseal/state.yaml.
type State struct {
	// LastCertFingerprint is the SHA256 fingerprint of the last used controller cert.
	// Used to detect cert rotations during reseal --all.
	LastCertFingerprint string `json:"lastCertFingerprintSha256,omitempty"`

	// Rotations is an audit trail of secret rotations.
	Rotations []Rotation `json:"rotations,omitempty"`

	// Retirements is an audit trail of secret retirements.
	Retirements []Retirement `json:"retirements,omitempty"`
}

// Rotation records a rotation or reseal operation.
type Rotation struct {
	ShortName  string `json:"shortName"`
	KeyName    string `json:"keyName,omitempty"`    // Optional, only for single-key rotations
	RotatedAt  string `json:"rotatedAt"`            // RFC3339
	Mode       string `json:"mode"`                 // "reseal" or "rotate"
	NewVersion string `json:"newVersion,omitempty"` // GSM version after rotation (if applicable)
}

// Retirement records a secret retirement.
type Retirement struct {
	ShortName  string `json:"shortName"`
	RetiredAt  string `json:"retiredAt"` // RFC3339
	Reason     string `json:"reason,omitempty"`
	ReplacedBy string `json:"replacedBy,omitempty"`
}

const stateFileName = "state.yaml"

// Load reads state from the .waxseal directory.
// Returns empty state if file doesn't exist.
func Load(repoPath string) (*State, error) {
	path := filepath.Join(repoPath, ".waxseal", stateFileName)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Return empty state if file doesn't exist
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}

	var s State
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes state to the .waxseal directory.
func (s *State) Save(repoPath string) error {
	path := filepath.Join(repoPath, ".waxseal", stateFileName)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}

	writer := files.NewAtomicWriter()
	return writer.Write(path, data)
}

// AddRotation adds a rotation record to the state.
// Keeps at most 100 entries to avoid unbounded growth.
func (s *State) AddRotation(shortName, keyName, mode, newVersion string) {
	r := Rotation{
		ShortName:  shortName,
		KeyName:    keyName,
		RotatedAt:  time.Now().UTC().Format(time.RFC3339),
		Mode:       mode,
		NewVersion: newVersion,
	}
	s.Rotations = append(s.Rotations, r)

	// Keep at most 100 entries
	if len(s.Rotations) > 100 {
		s.Rotations = s.Rotations[len(s.Rotations)-100:]
	}
}

// AddRetirement adds a retirement record to the state.
func (s *State) AddRetirement(shortName, reason, replacedBy string) {
	r := Retirement{
		ShortName:  shortName,
		RetiredAt:  time.Now().UTC().Format(time.RFC3339),
		Reason:     reason,
		ReplacedBy: replacedBy,
	}
	s.Retirements = append(s.Retirements, r)
}

// UpdateCertFingerprint updates the last known cert fingerprint.
func (s *State) UpdateCertFingerprint(fingerprint string) {
	s.LastCertFingerprint = fingerprint
}
