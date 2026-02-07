package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/spf13/cobra"
)

var gsmCmd = &cobra.Command{
	Use:   "gsm",
	Short: "GSM infrastructure management",
	Long:  `Commands for managing Google Secret Manager infrastructure for WaxSeal.`,
}

var gsmGCPBootstrapCmd = &cobra.Command{
	Use:   "gcp-bootstrap",
	Short: "Initialize GCP infrastructure for WaxSeal",
	Long: `Interactive wizard to set up GCP project with Secret Manager API and
required IAM permissions.

This command:
  1. Enables required APIs (Secret Manager, optionally Calendar)
  2. Creates a service account for WaxSeal operations
  3. Grants required IAM roles
  4. Sets up Workload Identity for GitHub Actions (optional)

Prerequisites:
  - gcloud CLI installed and authenticated
  - Project Owner or equivalent permissions
  - Billing account linked (for API enablement)

Use --dry-run to preview what would be done.`,
	RunE: runGCPBootstrap,
}

func init() {
	rootCmd.AddCommand(gsmCmd)
	gsmCmd.AddCommand(gsmGCPBootstrapCmd)
	gsmCmd.AddCommand(bootstrapCmd)
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

	// --- Interactive prompts ---

	// 1. Project setup: create or use existing?
	var setupChoice string
	err := huh.NewSelect[string]().
		Title("How do you want to set up GCP?").
		Options(
			huh.NewOption("Use an existing GCP project", "existing"),
			huh.NewOption("Create a new GCP project", "create"),
		).
		Value(&setupChoice).
		Run()
	if err != nil {
		return err
	}

	var projectID string
	var createProject bool
	var billingAccountID string
	var folderID string
	var orgID string

	if setupChoice == "create" {
		createProject = true

		// Prompt project ID
		err = huh.NewInput().
			Title("Project ID").
			Description("Globally unique GCP project identifier").
			Value(&projectID).
			Run()
		if err != nil {
			return err
		}
		if projectID == "" {
			return fmt.Errorf("project ID is required")
		}

		// Organization (optional)
		orgs, _ := gcp.GetOrganizations()
		if len(orgs) > 0 {
			var options []huh.Option[string]
			for _, o := range orgs {
				id := strings.TrimPrefix(o.Name, "organizations/")
				label := fmt.Sprintf("%s (%s)", o.DisplayName, id)
				options = append(options, huh.NewOption(label, id))
			}
			options = append(options, huh.NewOption("No Organization (standalone)", ""))
			err = huh.NewSelect[string]().
				Title("Organization").
				Description("Where to create the project").
				Options(options...).
				Value(&orgID).
				Run()
			if err != nil {
				return err
			}
		}

		// Billing account (required for new projects)
		accounts, _ := gcp.GetBillingAccounts()
		var billingOptions []huh.Option[string]
		for _, acc := range accounts {
			if acc.Open {
				id := strings.TrimPrefix(acc.Name, "billingAccounts/")
				label := fmt.Sprintf("%s (%s)", acc.DisplayName, id)
				billingOptions = append(billingOptions, huh.NewOption(label, id))
			}
		}

		if len(billingOptions) > 0 {
			billingOptions = append(billingOptions, huh.NewOption("Enter manually...", "manual"))
			err = huh.NewSelect[string]().
				Title("Billing Account").
				Description("Required for API enablement").
				Options(billingOptions...).
				Value(&billingAccountID).
				Run()
			if err != nil {
				return err
			}
		}

		if billingAccountID == "" || billingAccountID == "manual" {
			billingAccountID = ""
			err = huh.NewInput().
				Title("Billing Account ID").
				Description("Format: XXXXXX-XXXXXX-XXXXXX").
				Value(&billingAccountID).
				Run()
			if err != nil {
				return err
			}
		}

		if billingAccountID == "" {
			return fmt.Errorf("billing account is required to create a project")
		}
	} else {
		// Existing project — get project list or manual entry
		projects, _ := gcp.GetProjects()
		if len(projects) > 0 {
			var options []huh.Option[string]
			for _, p := range projects {
				label := fmt.Sprintf("%s (%s)", p.Name, p.ProjectID)
				options = append(options, huh.NewOption(label, p.ProjectID))
			}
			options = append(options, huh.NewOption("Enter manually...", "manual"))

			sel := huh.NewSelect[string]().
				Title("GCP Project").
				Options(options...).
				Value(&projectID).
				Filtering(true)
			if len(options) > 5 {
				sel.Height(8)
			}
			if err := sel.Run(); err != nil {
				return err
			}
		}

		if projectID == "" || projectID == "manual" {
			projectID = ""
			err = huh.NewInput().
				Title("Project ID").
				Description("Your existing GCP project ID").
				Value(&projectID).
				Run()
			if err != nil {
				return err
			}
		}

		if projectID == "" {
			return fmt.Errorf("project ID is required")
		}
	}

	// 2. Service account
	prefix := "waxseal"
	saID := prefix + "-sa"
	err = huh.NewInput().
		Title("Service Account ID").
		Description("Service account for WaxSeal operations").
		Value(&saID).
		Run()
	if err != nil {
		return err
	}
	saEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", saID, projectID)

	// 3. Enable reminders API?
	var enableReminders bool
	err = huh.NewConfirm().
		Title("Enable Google Calendar API for reminders?").
		Description("Allows WaxSeal to create expiry reminders in Google Calendar").
		Value(&enableReminders).
		Run()
	if err != nil {
		return err
	}

	// 4. Workload Identity for GitHub Actions?
	var githubRepo string
	var setupWIF bool
	err = huh.NewConfirm().
		Title("Set up Workload Identity for GitHub Actions?").
		Description("Enables keyless authentication from GitHub Actions CI/CD").
		Value(&setupWIF).
		Run()
	if err != nil {
		return err
	}
	if setupWIF {
		err = huh.NewInput().
			Title("GitHub Repository").
			Description("Format: owner/repo").
			Value(&githubRepo).
			Run()
		if err != nil {
			return err
		}
	}

	// --- Summary ---
	fmt.Println()
	fmt.Printf("WaxSeal GCP Bootstrap\n")
	fmt.Printf("═════════════════════\n")
	fmt.Printf("  Project:         %s\n", projectID)
	if createProject {
		fmt.Printf("  Create project:  yes\n")
	}
	fmt.Printf("  Service Account: %s\n", saEmail)
	if enableReminders {
		fmt.Printf("  Reminders API:   enabled\n")
	}
	if githubRepo != "" {
		fmt.Printf("  GitHub Repo:     %s\n", githubRepo)
	}
	fmt.Println()

	// Execute
	return executeGCPBootstrap(bootstrapParams{
		projectID:        projectID,
		createProject:    createProject,
		billingAccountID: billingAccountID,
		folderID:         folderID,
		orgID:            orgID,
		saID:             saID,
		enableReminders:  enableReminders,
		githubRepo:       githubRepo,
		prefix:           prefix,
	})
}

// bootstrapParams holds the parameters for GCP bootstrap execution.
// Used by both the interactive `gcp bootstrap` command and `setup`.
type bootstrapParams struct {
	projectID        string
	createProject    bool
	billingAccountID string
	folderID         string
	orgID            string
	saID             string
	enableReminders  bool
	githubRepo       string
	prefix           string
}

// executeGCPBootstrap runs the GCP bootstrap gcloud commands.
func executeGCPBootstrap(p bootstrapParams) error {
	saEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", p.saID, p.projectID)

	// Build commands
	var commands []gcloudCommand

	// 1. Create project (optional)
	if p.createProject {
		createArgs := []string{"projects", "create", p.projectID}
		if p.folderID != "" {
			createArgs = append(createArgs, "--folder="+p.folderID)
		} else if p.orgID != "" {
			createArgs = append(createArgs, "--organization="+p.orgID)
		}
		commands = append(commands, gcloudCommand{
			desc: "Create project",
			args: createArgs,
		})

		// Link billing
		commands = append(commands, gcloudCommand{
			desc: "Link billing account",
			args: []string{"billing", "projects", "link", p.projectID, "--billing-account=" + p.billingAccountID},
		})
	}

	// 2. Enable APIs
	apis := []string{"secretmanager.googleapis.com"}
	if p.enableReminders {
		apis = append(apis, "calendar-json.googleapis.com")
	}
	commands = append(commands, gcloudCommand{
		desc: "Enable APIs",
		args: append([]string{"services", "enable", "--project=" + p.projectID}, apis...),
	})

	// 3. Create service account
	commands = append(commands, gcloudCommand{
		desc: "Create service account",
		args: []string{"iam", "service-accounts", "create", p.saID,
			"--project=" + p.projectID,
			"--display-name=WaxSeal Service Account",
			"--description=Service account for WaxSeal SealedSecrets management"},
	})

	// 4. Grant Secret Manager Admin role
	commands = append(commands, gcloudCommand{
		desc: "Grant Secret Manager Admin",
		args: []string{"projects", "add-iam-policy-binding", p.projectID,
			"--member=serviceAccount:" + saEmail,
			"--role=roles/secretmanager.admin"},
	})

	// 5. Grant Calendar access (if enabled)
	if p.enableReminders {
		fmt.Println("Note: Calendar API enabled. Configure domain-wide delegation for reminders.")
	}

	// 6. Set up Workload Identity for GitHub Actions (optional)
	if p.githubRepo != "" {
		poolID := p.prefix + "-github-pool"
		providerID := p.prefix + "-github-provider"

		commands = append(commands, gcloudCommand{
			desc: "Create Workload Identity Pool",
			args: []string{"iam", "workload-identity-pools", "create", poolID,
				"--project=" + p.projectID,
				"--location=global",
				"--display-name=GitHub Actions Pool"},
		})

		commands = append(commands, gcloudCommand{
			desc: "Create OIDC Provider",
			args: []string{"iam", "workload-identity-pools", "providers", "create-oidc", providerID,
				"--project=" + p.projectID,
				"--location=global",
				"--workload-identity-pool=" + poolID,
				"--display-name=GitHub Actions",
				"--issuer-uri=https://token.actions.githubusercontent.com",
				"--attribute-mapping=google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository",
			},
		})

		poolPath := fmt.Sprintf("principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.repository/%s",
			p.projectID, poolID, p.githubRepo)
		commands = append(commands, gcloudCommand{
			desc: "Bind service account to Workload Identity",
			args: []string{"iam", "service-accounts", "add-iam-policy-binding", saEmail,
				"--project=" + p.projectID,
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
				if strings.Contains(errMsg, "already exists") {
					printSuccess("%s (already done)", c.desc)
				} else if strings.Contains(errMsg, "already in use") {
					return fmt.Errorf("project_collision")
				} else {
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
		printSuccess("GCP bootstrap complete for project %s", p.projectID)
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
