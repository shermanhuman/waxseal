package core

import (
	"strings"
	"testing"
	"time"
)

func TestEnum_Validate(t *testing.T) {
	if err := RotationModes.Validate("rotation.mode", RotationExternal); err != nil {
		t.Errorf("valid value rejected: %v", err)
	}
	err := RotationModes.Validate("rotation.mode", "manual")
	if err == nil {
		t.Fatal("expected an error")
	}
	// The message has to tell the user what they may type.
	for _, want := range []string{"manual", "generated", "external", "static", "unknown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestEnum_OpenAcceptsAnyNonEmptyValue(t *testing.T) {
	if !SecretTypes.Has("example.com/custom") {
		t.Error("open enum rejected a custom value")
	}
	if SecretTypes.Has("") {
		t.Error("open enum accepted an empty value")
	}
}

func TestEnum_OnlyKeepsTableOrder(t *testing.T) {
	got := RotationModes.Only(RotationStatic, RotationGenerated).Values()
	if len(got) != 2 || got[0] != RotationGenerated || got[1] != RotationStatic {
		t.Errorf("Only() = %v, want [generated static]", got)
	}
	if OfferedGeneratorKinds.Has(GeneratorRandomBytes) {
		t.Error("raw bytes must not be offered by the CLI")
	}
	if !GeneratorKinds.Has(GeneratorRandomBytes) {
		t.Error("raw bytes must stay valid in existing metadata")
	}
}

func TestKeyHelpers(t *testing.T) {
	plain := &GSMRef{SecretResource: "projects/p/secrets/a", Version: "1"}
	payload := &GSMRef{SecretResource: "projects/p/secrets/b", Version: "2"}
	m := &SecretMetadata{Keys: []KeyMetadata{
		{KeyName: "a", GSM: plain},
		{KeyName: "b", Computed: &ComputedConfig{GSM: payload}},
		{KeyName: "c", Computed: &ComputedConfig{Inputs: []InputRef{{Var: "x"}}}},
	}}

	if m.Key("missing") != nil {
		t.Error("Key() should be nil for an unknown key")
	}
	if got := m.Key("a").ActiveRef(); got != plain {
		t.Errorf("gsm key: ActiveRef() = %v", got)
	}
	if got := m.Key("b").ActiveRef(); got != payload {
		t.Errorf("computed key with payload: ActiveRef() = %v", got)
	}
	if got := m.Key("c").ActiveRef(); got != nil {
		t.Errorf("derived key: ActiveRef() = %v, want nil", got)
	}

	// Key returns a pointer into the slice so callers can update in place.
	m.Key("a").GSM.Version = "9"
	if m.Keys[0].GSM.Version != "9" {
		t.Error("Key() must not return a copy")
	}
}

func TestExpiresBefore(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m := &SecretMetadata{Keys: []KeyMetadata{
		{KeyName: "never"},
		{KeyName: "garbage", Expiry: &ExpiryConfig{ExpiresAt: "soon"}},
		{KeyName: "june15", Expiry: &ExpiryConfig{ExpiresAt: "2026-06-15T00:00:00Z"}},
	}}

	if m.ExpiresBefore(now) {
		t.Error("nothing has expired yet")
	}
	if !m.ExpiresBefore(now.AddDate(0, 0, 30)) {
		t.Error("june15 expires within 30 days")
	}
	if m.ExpiresBefore(now.AddDate(0, 0, 7)) {
		t.Error("june15 does not expire within 7 days")
	}
	if _, ok := m.Key("garbage").ExpiresAt(); ok {
		t.Error("an unparseable expiry must not count as a time")
	}
}
