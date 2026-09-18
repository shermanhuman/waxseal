// Package seal builds SealedSecret manifests and encrypts values for them.
// Encryption is delegated to the kubeseal binary so ciphertext is exactly
// what the controller expects.
package seal

import "fmt"

// Sealer encrypts a single key's value for a SealedSecret.
type Sealer interface {
	// Seal encrypts value for the named secret. scope selects the label the
	// ciphertext is bound to (strict, namespace-wide or cluster-wide).
	Seal(name, namespace, key string, value []byte, scope string) (string, error)
}

// FakeSealer is a test implementation that returns predictable output.
type FakeSealer struct {
	// Prefix to add to "encrypted" values for testing
	Prefix string
	// FailKeys maps a key name to the error Seal returns for it.
	FailKeys map[string]error
}

// NewFakeSealer creates a fake sealer for testing.
func NewFakeSealer() *FakeSealer {
	return &FakeSealer{Prefix: "SEALED:"}
}

// Seal returns a deterministic fake encrypted value.
func (s *FakeSealer) Seal(name, namespace, key string, value []byte, scope string) (string, error) {
	if err := s.FailKeys[key]; err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s/%s/%s=%s", s.Prefix, namespace, name, key, string(value)), nil
}

var _ Sealer = (*FakeSealer)(nil)
