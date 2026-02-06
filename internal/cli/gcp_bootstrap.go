package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh/spinner"
	"github.com/shermanhuman/waxseal/internal/gcp"
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
	if err := gcp.CheckGcloudInstalled(); err != nil {
		return err
	}

	// Ensure authed
	if err := EnsureGcloudAuth(); err != nil {
		return err
	}

	// Ensure ADC (required for Go SDK)
	if err := EnsureGcloudADC(); err != nil {
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
			var runErr error
			_ = spinner.New().
				Title(fmt.Sprintf("%s...", c.desc)).
				Type(spinner.Dots).
				Action(func() {
					runErr = gcp.RunGcloud(c.args...)
				}).
				Run()

			if runErr != nil {
				errMsg := strings.ToLower(runErr.Error())
				// If it's an "already exists" error (local idempotency), we can proceed
				// "Project '...' already exists." -> We likely own it.
				if strings.Contains(errMsg, "already exists") {
					printSuccess("%s (already done)", c.desc)
				} else if strings.Contains(errMsg, "already in use") {
					// "Project ID ... is already in use by another project." -> Global conflict.
					// We return a specific error so init.go can handle it.
					return fmt.Errorf("project_collision")
				} else {
					// Critical failure - stop execution
					return fmt.Errorf("step '%s' failed: %v", c.desc, runErr)
				}
			} else {
				printSuccess("%s", c.desc)
			}
		}
	}

	fmt.Println()
	if dryRun {
		fmt.Println("[DRY RUN] Would complete GCP bootstrap")
	} else {
		printSuccess("GCP bootstrap complete for project %s", gcpProjectID)
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Printf("  1. Run 'waxseal setup --project-id %s'\n", gcpProjectID)
		fmt.Println("  2. Run 'waxseal discover' to find existing SealedSecrets")
	}

	return nil
}

type gcloudCommand struct {
	desc string
	args []string
}

func CheckKubesealInstalled() error {
	_, err := exec.LookPath("kubeseal")
	if err != nil {
		printWarning("'kubeseal' CLI not found in PATH.")
		fmt.Println("  WaxSeal requires 'kubeseal' to encrypt secrets for Kubernetes.")
		fmt.Println("  Install it from: https://github.com/bitnami-labs/sealed-secrets/releases")
		fmt.Println()
	}
	return nil
}

func EnsureGcloudADC(scopes ...string) error {
if gcp.ADCExists() {
return nil
}

fmt.Println("Application Default Credentials (ADC) missing.")
fmt.Println("  (Note: This is separate from 'gcloud auth login'. ADC is required for WaxSeal to call APIs.)")

if len(scopes) > 0 {
fmt.Println("Additional access scopes required: " + strings.Join(scopes, ", "))
} else {
fmt.Println("WaxSeal needs these credentials to talk to Secret Manager.")
}

ok, err := confirm("Run 'gcloud auth application-default login' now?")
if err != nil {
return err
}
if !ok {
printWarning("Without ADC, 'reseal' and 'rotate' will fail unless GOOGLE_APPLICATION_CREDENTIALS is set.")
return nil
}

fmt.Println("Launching browser for authentication...")
hasCalendarScope := false
for _, s := range scopes {
if strings.Contains(s, "calendar") {
hasCalendarScope = true
break
}
}
if hasCalendarScope {
fmt.Println("Please sign in with the Google Account that owns the calendar you want to use.")
}
fmt.Println()
fmt.Println("Running 'gcloud auth application-default login'...")

args := []string{"auth", "application-default", "login"}
if len(scopes) > 0 {
args = append(args, "--scopes="+strings.Join(scopes, ","))
}

if err := gcp.RunGcloud(args...); err != nil {
printWarning("ADC login failed: %v", err)
}
return nil
}

func EnsureGcloudAuth() error {
for {
if account := gcp.ActiveAccount(); account != "" {
return nil
}

fmt.Println("GCP credentials not found. WaxSeal requires an active gcloud account.")
ok, err := confirm("Run 'gcloud auth login' now?")
if err != nil {
return err
}
if !ok {
return fmt.Errorf("gcloud authentication required to continue")
}

fmt.Println("Running 'gcloud auth login'...")
if err := gcp.RunGcloud("auth", "login"); err != nil {
printWarning("gcloud login failed: %v", err)
fmt.Println("Please try again or authenticate manually.")
continue
}

fmt.Println("Verifying authentication...")
}
}