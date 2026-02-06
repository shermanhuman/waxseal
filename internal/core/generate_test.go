package core

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestGenerateValue_RandomBase64(t *testing.T) {
	gen := &GeneratorConfig{
		Kind:  "randomBase64",
		Bytes: 32,
	}

	value, err := GenerateValue(gen)
	if err != nil {
		t.Fatalf("GenerateValue failed: %v", err)
	}

	// Should be valid base64
	decoded, err := base64.StdEncoding.DecodeString(string(value))
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("decoded length = %d, want 32", len(decoded))
	}
}

func TestGenerateValue_RandomHex(t *testing.T) {
	gen := &GeneratorConfig{
		Kind:  "randomHex",
		Bytes: 16,
	}

	value, err := GenerateValue(gen)
	if err != nil {
		t.Fatalf("GenerateValue failed: %v", err)
	}

	// Should be valid hex
	decoded, err := hex.DecodeString(string(value))
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("decoded length = %d, want 16", len(decoded))
	}
}

func TestGenerateValue_RandomBytes(t *testing.T) {
	gen := &GeneratorConfig{
		Kind:  "randomBytes",
		Bytes: 24,
	}

	value, err := GenerateValue(gen)
	if err != nil {
		t.Fatalf("GenerateValue failed: %v", err)
	}

	if len(value) != 24 {
		t.Errorf("value length = %d, want 24", len(value))
	}
}

func TestGenerateValue_DefaultBytes(t *testing.T) {
	gen := &GeneratorConfig{
		Kind: "randomBase64",
		// No bytes specified
	}

	value, err := GenerateValue(gen)
	if err != nil {
		t.Fatalf("GenerateValue failed: %v", err)
	}

	decoded, _ := base64.StdEncoding.DecodeString(string(value))
	if len(decoded) != 32 { // Default should be 32
		t.Errorf("decoded length = %d, want 32 (default)", len(decoded))
	}
}

func TestGenerateValue_Randomness(t *testing.T) {
	gen := &GeneratorConfig{
		Kind:  "randomBase64",
		Bytes: 32,
	}

	// Generate multiple values - should all be different
	values := make(map[string]bool)
	for i := 0; i < 10; i++ {
		value, _ := GenerateValue(gen)
		if values[string(value)] {
			t.Error("generated duplicate value - randomness failure")
		}
		values[string(value)] = true
	}
}

func TestGenerateValue_UnsupportedKind(t *testing.T) {
	gen := &GeneratorConfig{
		Kind:  "unsupported",
		Bytes: 32,
	}

	_, err := GenerateValue(gen)
	if err == nil {
		t.Error("expected error for unsupported generator kind")
	}
}

func TestGenerateValue_NilGenerator(t *testing.T) {
	_, err := GenerateValue(nil)
	if err == nil {
		t.Error("expected error for nil generator")
	}
}
