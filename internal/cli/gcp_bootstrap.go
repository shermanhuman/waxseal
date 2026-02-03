package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "GCP infrastructure management",
	Long:  `Commands for managing GCP infrastructure for WaxSeal.`,
}

var gcpBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Initialize GCP infrastructure for WaxSeal",
	Long: `Set up GCP project with Secret Manager API and required IAM permissions.

This command:
  1. Enables required APIs (Secret Manager, optionally Calendar)
  2. Creates a service account for WaxSeal operations
  3. Grants required IAM roles
  4. Sets up Workload Identity for GitHub Actions (optional)

Prerequisites:
  - gcloud CLI installed and authenticated
  - Project Owner or equivalent permissions
  - Billing account linked (for API enablement)

Examples:
  # Bootstrap existing project
  waxseal gcp bootstrap --project-id my-project

  # Create new project and bootstrap
  waxseal gcp bootstrap --project-id my-project --create-project --billing-account-id 01XXXX-XXXXXX-XXXXXX

  # Preview what would be done
  waxseal gcp bootstrap --project-id my-project --dry-run

  # Enable calendar reminders API
  waxseal gcp bootstrap --project-id my-project --enable-reminders-api`,
	RunE: runGCPBootstrap,
}

var (
	gcpProjectID        string
	gcpCreateProject    bool
	gcpBillingAccountID string
	gcpFolderID         string
	gcpOrgID            string
	gcpGitHubRepo       string
	gcpDefaultBranchRef string
	gcpEnableReminders  bool
	gcpSecretsPrefix    string
	gcpServiceAccountID string
)

func init() {
	rootCmd.AddCommand(gcpCmd)
	gcpCmd.AddCommand(gcpBootstrapCmd)

	gcpBootstrapCmd.Flags().StringVar(&gcpProjectID, "project-id", "", "GCP project ID (required)")
	gcpBootstrapCmd.Flags().BoolVar(&gcpCreateProject, "create-project", false, "Create the project if it doesn't exist")
	gcpBootstrapCmd.Flags().StringVar(&gcpBillingAccountID, "billing-account-id", "", "Billing account ID (required with --create-project)")
	gcpBootstrapCmd.Flags().StringVar(&gcpFolderID, "folder-id", "", "Folder ID for project organization")
	gcpBootstrapCmd.Flags().StringVar(&gcpOrgID, "org-id", "", "Organization ID for project")
	gcpBootstrapCmd.Flags().StringVar(&gcpGitHubRepo, "github-repo", "", "GitHub repository for Workload Identity (owner/repo)")
	gcpBootstrapCmd.Flags().StringVar(&gcpDefaultBranchRef, "default-branch-ref", "refs/heads/main", "Default branch ref for Workload Identity")
	gcpBootstrapCmd.Flags().BoolVar(&gcpEnableReminders, "enable-reminders-api", false, "Enable Google Calendar API for reminders")
	gcpBootstrapCmd.Flags().StringVar(&gcpSecretsPrefix, "secrets-prefix", "waxseal", "Prefix for service account and secrets")
	gcpBootstrapCmd.Flags().StringVar(&gcpServiceAccountID, "service-account-id", "", "Service account ID (default: <prefix>-sa)")

	gcpBootstrapCmd.MarkFlagRequired("project-id")
}

func runGCPBootstrap(cmd *cobra.Command, args []string) error {
	// Check for gcloud
	if err := checkGcloudInstalled(); err != nil {
		return err
	}

	// Validate flags
	if gcpCreateProject && gcpBillingAccountID == "" {
		return fmt.Errorf("--billing-account-id is required when --create-project is set")
	}

	saID := gcpServiceAccountID
	if saID == "" {
		saID = gcpSecretsPrefix + "-sa"
	}
	saEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", saID, gcpProjectID)

	fmt.Printf("WaxSeal GCP Bootstrap\n")
	fmt.Printf("=====================\n")
	fmt.Printf("Project:         %s\n", gcpProjectID)
	fmt.Printf("Service Account: %s\n", saEmail)
	if gcpEnableReminders {
		fmt.Printf("Reminders API:   enabled\n")
	}
	if gcpGitHubRepo != "" {
		fmt.Printf("GitHub Repo:     %s\n", gcpGitHubRepo)
	}
	fmt.Println()

	// Build commands
	var commands []gcloudCommand

	// 1. Create project (optional)
	if gcpCreateProject {
		createArgs := []string{"projects", "create", gcpProjectID}
		if gcpFolderID != "" {
			createArgs = append(createArgs, "--folder="+gcpFolderID)
		} else if gcpOrgID != "" {
			createArgs = append(createArgs, "--organization="+gcpOrgID)
		}
		commands = append(commands, gcloudCommand{
			desc: "Create project",
			args: createArgs,
		})

		// Link billing
		commands = append(commands, gcloudCommand{
			desc: "Link billing account",
			args: []string{"billing", "projects", "link", gcpProjectID, "--billing-account=" + gcpBillingAccountID},
		})
	}

	// 2. Enable APIs
	apis := []string{"secretmanager.googleapis.com"}
	if gcpEnableReminders {
		apis = append(apis, "calendar-json.googleapis.com")
	}
	commands = append(commands, gcloudCommand{
		desc: "Enable APIs",
		args: append([]string{"services", "enable", "--project=" + gcpProjectID}, apis...),
	})

	// 3. Create service account
	commands = append(commands, gcloudCommand{
		desc: "Create service account",
		args: []string{"iam", "service-accounts", "create", saID,
			"--project=" + gcpProjectID,
			"--display-name=WaxSeal Service Account",
			"--description=Service account for WaxSeal SealedSecrets management"},
	})

	// 4. Grant Secret Manager Admin role
	commands = append(commands, gcloudCommand{
		desc: "Grant Secret Manager Admin",
		args: []string{"projects", "add-iam-policy-binding", gcpProjectID,
			"--member=serviceAccount:" + saEmail,
			"--role=roles/secretmanager.admin"},
	})

	// 5. Grant Calendar access (if enabled)
	if gcpEnableReminders {
		// Note: Calendar API requires domain-wide delegation for service accounts
		// This just grants the ability to use the API
		fmt.Println("Note: Calendar API enabled. Configure domain-wide delegation for reminders.")
	}

	// 6. Set up Workload Identity for GitHub Actions (optional)
	if gcpGitHubRepo != "" {
		// Create Workload Identity Pool
		poolID := gcpSecretsPrefix + "-github-pool"
		providerID := gcpSecretsPrefix + "-github-provider"

		commands = append(commands, gcloudCommand{
			desc: "Create Workload Identity Pool",
			args: []string{"iam", "workload-identity-pools", "create", poolID,
				"--project=" + gcpProjectID,
				"--location=global",
				"--display-name=GitHub Actions Pool"},
		})

		commands = append(commands, gcloudCommand{
			desc: "Create OIDC Provider",
			args: []string{"iam", "workload-identity-pools", "providers", "create-oidc", providerID,
				"--project=" + gcpProjectID,
				"--location=global",
				"--workload-identity-pool=" + poolID,
				"--display-name=GitHub Actions",
				"--issuer-uri=https://token.actions.githubusercontent.com",
				"--attribute-mapping=google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository",
			},
		})

		// Bind service account to workload identity
		poolPath := fmt.Sprintf("principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.repository/%s",
			gcpProjectID, poolID, gcpGitHubRepo)
		commands = append(commands, gcloudCommand{
			desc: "Bind service account to Workload Identity",
			args: []string{"iam", "service-accounts", "add-iam-policy-binding", saEmail,
				"--project=" + gcpProjectID,
				"--member=" + poolPath,
				"--role=roles/iam.workloadIdentityUser"},
		})
	}

	// Execute or dry-run
	for _, c := range commands {
		if dryRun {
			fmt.Printf("[DRY RUN] %s\n", c.desc)
			fmt.Printf("  gcloud %s\n\n", strings.Join(c.args, " "))
		} else {
			fmt.Printf("→ %s...\n", c.desc)
			if err := runGcloud(c.args...); err != nil {
				// Some errors are expected (already exists), continue
				if !strings.Contains(err.Error(), "already exists") {
					fmt.Printf("  ⚠ Warning: %v\n", err)
				} else {
					fmt.Printf("  Already exists, skipping\n")
				}
			} else {
				fmt.Printf("  ✓ Done\n")
			}
		}
	}

	fmt.Println()
	if dryRun {
		fmt.Println("[DRY RUN] Would complete GCP bootstrap")
	} else {
		fmt.Printf("✓ GCP bootstrap complete for project %s\n", gcpProjectID)
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Printf("  1. Run 'waxseal init --store-project-id %s'\n", gcpProjectID)
		fmt.Println("  2. Run 'waxseal discover' to find existing SealedSecrets")
	}

	return nil
}

type gcloudCommand struct {
	desc string
	args []string
}

func checkGcloudInstalled() error {
	_, err := exec.LookPath("gcloud")
	if err != nil {
		return fmt.Errorf(`gcloud CLI not found in PATH

Please install the Google Cloud SDK:
  https://cloud.google.com/sdk/docs/install

Then authenticate:
  gcloud auth login
  gcloud auth application-default login`)
	}
	return nil
}

func runGcloud(args ...string) error {
	cmd := exec.Command("gcloud", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
