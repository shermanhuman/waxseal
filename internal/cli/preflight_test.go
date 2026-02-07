package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestPreflightBinary_Found(t *testing.T) {
	// "go" should always be available when running tests
	err := preflightBinary("go", "Go is required", "https://go.dev")
	if err != nil {
		t.Fatalf("expected no error for 'go' binary, got: %v", err)
	}
}

func TestPreflightBinary_NotFound(t *testing.T) {
	err := preflightBinary("waxseal-nonexistent-binary-xyz", "test reason", "https://example.com")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestAddPreflightChecks_ChainsWithExistingPreRunE(t *testing.T) {
	existingCalled := false

	cmd := &cobra.Command{
		Use: "test",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			existingCalled = true
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// No auth requirements — should just chain through
	addPreflightChecks(cmd, authNeeds{})
	_ = cmd.PreRunE(cmd, nil)

	if !existingCalled {
		t.Error("existing PreRunE was not called after addPreflightChecks")
	}
}

func TestAuthNeeds_ZeroValueMeansNoChecks(t *testing.T) {
	needs := authNeeds{}
	if needs.gsm || needs.kubeseal || needs.kubectl {
		t.Error("zero-value authNeeds should require nothing")
	}
}
