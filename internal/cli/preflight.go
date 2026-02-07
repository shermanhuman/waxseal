package cli

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/spf13/cobra"
)

// authNeeds describes what external auth a command requires.
type authNeeds struct {
	gsm      bool // Google Secret Manager (requires gcloud + valid ADC)
	kubeseal bool // kubeseal binary on PATH
	kubectl  bool // kubectl binary on PATH
}

// addPreflightChecks decorates a command's PreRunE to verify auth prerequisites
// before the command body runs. If auth is missing or expired, the user is
// prompted to fix it inline rather than hitting a cryptic gRPC error mid-run.
func addPreflightChecks(cmd *cobra.Command, needs authNeeds) {
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()

		if needs.gsm {
			if err := preflightGSM(ctx); err != nil {
				return err
			}
		}

		if needs.kubeseal {
			if err := preflightBinary("kubeseal",
				"WaxSeal requires 'kubeseal' to encrypt secrets for Kubernetes.",
				"https://github.com/bitnami-labs/sealed-secrets/releases"); err != nil {
				return err
			}
		}

		if needs.kubectl {
			if err := preflightBinary("kubectl",
				"This operation requires 'kubectl' to talk to the cluster.",
				"https://kubernetes.io/docs/tasks/tools/"); err != nil {
				return err
			}
		}

		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}

// preflightGSM ensures the user can reach Google Secret Manager:
//  1. gcloud CLI installed
//  2. gcloud account active (offers login if not)
//  3. ADC token valid — not just present on disk (offers re-login if expired)
func preflightGSM(ctx context.Context) error {
	// 1. gcloud installed?
	if err := gcp.CheckGcloudInstalled(); err != nil {
		return err
	}

	// 2. Logged in to gcloud?
	if err := EnsureGcloudAuth(); err != nil {
		return err
	}

	// 3. ADC token valid?  (catches expired / revoked tokens)
	if err := gcp.ADCTokenValid(ctx); err != nil {
		printWarning("GCP Application Default Credentials are invalid or expired.")
		fmt.Println()

		ok, confirmErr := confirm("Run 'gcloud auth application-default login' to re-authenticate?")
		if confirmErr != nil {
			return confirmErr
		}
		if !ok {
			return fmt.Errorf("valid GCP credentials required — run 'gcloud auth application-default login'")
		}

		fmt.Println()
		fmt.Println("Running 'gcloud auth application-default login'...")
		if err := gcp.RunGcloud("auth", "application-default", "login"); err != nil {
			return fmt.Errorf("re-authentication failed: %w", err)
		}

		// Verify the new credentials actually work
		if err := gcp.ADCTokenValid(ctx); err != nil {
			return fmt.Errorf("credentials still invalid after login: %w", err)
		}

		printSuccess("GCP credentials refreshed")
		fmt.Println()
	}

	return nil
}

// preflightBinary checks that a required binary is on PATH and returns
// a clear error with install instructions if it's missing.
func preflightBinary(name, reason, installURL string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("'%s' not found in PATH\n\n  %s\n  Install: %s", name, reason, installURL)
	}
	return nil
}
