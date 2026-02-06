package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateValue produces a random value encoded according to gen.Kind.
//
// Supported kinds:
//   - "randomBase64": base64-encoded random bytes
//   - "randomHex":    hex-encoded random bytes
//   - "randomBytes":  raw random bytes
//
// If gen.Bytes is 0, defaults to 32 bytes of randomness.
func GenerateValue(gen *GeneratorConfig) ([]byte, error) {
	if gen == nil {
		return nil, fmt.Errorf("no generator config")
	}

	byteCount := gen.Bytes
	if byteCount == 0 {
		byteCount = 32 // Default to 32 bytes
	}

	// Generate random bytes
	randomBytes := make([]byte, byteCount)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}

	// Encode based on kind
	switch gen.Kind {
	case "randomBase64":
		return []byte(base64.StdEncoding.EncodeToString(randomBytes)), nil
	case "randomHex":
		return []byte(hex.EncodeToString(randomBytes)), nil
	case "randomBytes":
		return randomBytes, nil
	default:
		return nil, fmt.Errorf("unsupported generator kind: %s", gen.Kind)
	}
}
