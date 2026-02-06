package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/shermanhuman/waxseal/internal/files"
	"github.com/shermanhuman/waxseal/internal/gcp"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup wizard for waxseal",
	Long: `Interactive setup wizard for waxseal in a GitOps repository.

This wizard walks you through:
  1. GCP Project Setup     - Configure or create a GCP project
  2. Controller Discovery  - Find your SealedSecrets controller
  3. Certificate Fetch     - Download the controller's public cert
  4. Secret Discovery      - Find existing SealedSecret manifests
  5. Key Configuration     - Configure rotation for each secret key
  6. Bootstrap to GSM      - Push secret values to Google Secret Manager
  7. Reminders Setup       - Set up expiration reminders (optional)

Files created:
  - .waxseal/config.yaml - Main configuration file
  - .waxseal/metadata/   - Directory for secret metadata
  - keys/pub-cert.pem    - Controller certificate

The setup wizard is fully interactive — it walks you through all configuration.`,
	RunE: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func runSetup(cmd *cobra.Command, args []string) error {
	waxsealDir := filepath.Join(repoPath, ".waxseal")
	metadataDir := filepath.Join(waxsealDir, "metadata")
	keysDir := filepath.Join(repoPath, "keys")
	configFile := filepath.Join(waxsealDir, "config.yaml")

	// Check if this looks like a project root
	{
		gitDir := filepath.Join(repoPath, ".git")
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			fmt.Println()
		printWarning("No .git folder found in this directory.")
			fmt.Println()

			var continueAnyway bool
			err := huh.NewConfirm().
				Title("Continue anyway?").
				Value(&continueAnyway).
				Run()
			if err != nil {
				return err
			}
			if !continueAnyway {
				fmt.Println("Aborted. Please cd to your repository root and run 'waxseal setup' again.")
				return nil
			}
		}
	}

	// Check if already initialized
	if _, err := os.Stat(configFile); err == nil && !yes {
		fmt.Printf("waxseal already initialized at %s\n", waxsealDir)
		if !confirmOverwrite() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Check for prerequisites (always, even non-interactive)
	if err := CheckKubesealInstalled(); err != nil {
		return err
	}

	// Welcome message
	{
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    Welcome to WaxSeal                        ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("WaxSeal syncs your Kubernetes SealedSecrets with Google Secret Manager.")
		fmt.Println("Secret values are stored in GCP - only encrypted ciphertext goes in Git.")
		fmt.Println()
		fmt.Println("This wizard will walk you through 7 steps:")
		fmt.Println("  1. GCP Project Setup     - Configure or create a GCP project")
		fmt.Println("  2. Controller Discovery  - Find your SealedSecrets controller")
		fmt.Println("  3. Certificate Fetch     - Download the controller's public cert")
		fmt.Println("  4. Secret Discovery      - Find existing SealedSecret manifests")
		fmt.Println("  5. Key Configuration     - Configure rotation for each secret key")
		fmt.Println("  6. Bootstrap to GSM      - Push secret values to Google Secret Manager")
		fmt.Println("  7. Reminders Setup       - Set up expiration reminders (optional)")
		fmt.Println()
	}

	// Handle GCP setup
	var projectID string
	{
		printStep(1, 7, "GCP Project Setup")
		fmt.Println()

		// Project setup choice
		var setupChoice string
		err := huh.NewSelect[string]().
			Title("How do you want to set up GCP?").
			Options(
				huh.NewOption("Create a new GCP project (fully automated)", "create"),
				huh.NewOption("Use an existing GCP project", "existing"),
			).
			Value(&setupChoice).
			Run()
		if err != nil {
			return err
		}

		if setupChoice == "create" {
			// Check for gcloud before proceeding
			if err := gcp.CheckGcloudInstalled(); err != nil {
				return err
			}

			// Ensure auth before fetching billing accounts
			if err := EnsureGcloudAuth(); err != nil {
				return err
			}

			// 0. Resolve Organization (optional)
			var orgID string
			orgs, _ := gcp.GetOrganizations()
			if len(orgs) > 0 {
				fmt.Printf("Found %d organizations.\n", len(orgs))
				var options []huh.Option[string]
				for _, o := range orgs {
					// Name is "organizations/12345", we need "12345"
					id := strings.TrimPrefix(o.Name, "organizations/")
					label := fmt.Sprintf("%s (%s)", o.DisplayName, id)
					options = append(options, huh.NewOption(label, id))
				}
				options = append(options, huh.NewOption("No Organization (Standalone)", ""))

				sel := huh.NewSelect[string]().
					Title("Organization").
					Description("Select where to create the project").
					Options(options...).
					Value(&orgID).
					Filtering(true)

				if len(options) > 5 {
					sel.Height(8)
				}

				err = sel.Run()
				if err != nil {
					return err
				}
			}

			// 1. Resolve Billing Account (Before project loop)
			var billingID string

			// Try to fetch available accounts
			accounts, _ := gcp.GetBillingAccounts()
			var billingOptions []huh.Option[string]
			for _, acc := range accounts {
				if acc.Open {
					id := strings.TrimPrefix(acc.Name, "billingAccounts/")
					label := fmt.Sprintf("%s (%s)", acc.DisplayName, id)
					billingOptions = append(billingOptions, huh.NewOption(label, id))
				}
			}
			billingOptions = append(billingOptions, huh.NewOption("Enter manually...", "manual"))

			// If we found accounts, let user choose
			if len(billingOptions) > 1 {
				var choice string
				err = huh.NewSelect[string]().
					Title("Billing Account").
					Options(billingOptions...).
					Value(&choice).
					Run()
				if err != nil {
					return err
				}
				if choice != "manual" {
					billingID = choice
				}
			}

			// Fallback to manual input
			if billingID == "" {
				err = huh.NewInput().
					Title("Billing Account ID").
					Description("Format: 01XXXX-XXXXXX-XXXXXX (see console.cloud.google.com/billing)").
					Value(&billingID).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("billing ID is required")
						}
						return nil
					}).
					Run()
				if err != nil {
					return err
				}
			}

			// Project Creation Loop
			for {
				if projectID == "" {
					err = huh.NewInput().
						Title("Desired Project ID").
						Description("Lower-case slug (e.g. waxseal-prod-secrets)").
						Value(&projectID).
						Validate(func(s string) error {
							if s == "" {
								return fmt.Errorf("project ID is required")
							}
							if len(s) < 6 || len(s) > 30 {
								return fmt.Errorf("project ID must be between 6 and 30 characters")
							}
							match, _ := regexp.MatchString("^[a-z][a-z0-9-]*$", s)
							if !match {
								return fmt.Errorf("project ID must start with a letter and contain only lowercase letters, digits, and hyphens")
							}
							return nil
						}).
						Run()
					if err != nil {
						return err
					}
				}

				// Run bootstrap
				err := executeGCPBootstrap(bootstrapParams{
					projectID:        projectID,
					createProject:    true,
					billingAccountID: billingID,
					orgID:            orgID,
					saID:             "waxseal-sa",
					prefix:           "waxseal",
				})
				if err == nil {
					// Success
					fmt.Println()
				printSuccess("GCP Project created and bootstrapped.")
					fmt.Println("Proceeding with WaxSeal initialization...")
					fmt.Println()
					break
				}

				// Handle Collisions
				if strings.Contains(strings.ToLower(err.Error()), "project_collision") {
					var resolution string
					err = huh.NewSelect[string]().
						Title(fmt.Sprintf("Project ID '%s' is unavailable.", projectID)).
						Description("It is already in use by another project (globally).").
						Options(
							huh.NewOption("Try a different Project ID", "retry"),
							huh.NewOption(fmt.Sprintf("Use existing project '%s' (if you own it)", projectID), "use_existing"),
							huh.NewOption("Select another existing project", "select_existing"),
						).
						Value(&resolution).
						Run()
					if err != nil {
						return err
					}

					if resolution == "use_existing" {
						setupChoice = "existing"
						// Break loop; projectID is set, fall through to "existing" logic
						break
					} else if resolution == "select_existing" {
						setupChoice = "existing"
						projectID = "" // Clear so we get the list
						break
					}
					// Retry
					projectID = ""
					continue
				} else {
					return fmt.Errorf("bootstrap failed: %w", err)
				}
			}
		}

		if setupChoice == "existing" {
			// Ensure authed even for existing project since discover/add will need it
			if err := EnsureGcloudAuth(); err != nil {
				return err
			}
			if err := EnsureGcloudADC(); err != nil {
				return err
			}

			// Try to list projects only if we need one
			if projectID == "" {
				projects, _ := gcp.GetProjects()
				var options []huh.Option[string]
				for _, p := range projects {
					label := fmt.Sprintf("%s (%s)", p.Name, p.ProjectID)
					options = append(options, huh.NewOption(label, p.ProjectID))
				}
				options = append(options, huh.NewOption("Enter manually...", "manual"))

				if len(options) > 1 {
					var choice string
					err = huh.NewSelect[string]().
						Title("Select GCP Project").
						Options(options...).
						Value(&choice).
						Filtering(true).
						Run()
					if err != nil {
						return err
					}
					if choice != "manual" {
						projectID = choice
					}
				}
			}

			if projectID == "" {
				err = huh.NewInput().
					Title("GCP Project ID").
					Description("The human-readable project slug (e.g. my-app-prod)").
					Value(&projectID).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("project ID is required")
						}
						return nil
					}).
					Run()
				if err != nil {
					return err
				}
			}
		}
	}
	if projectID == "" {
		return fmt.Errorf("GCP project ID is required; re-run the setup wizard")
	}

	// Check billing and enable APIs (for existing project path)
	if projectID != "" {
		// Check if billing is enabled
		var billingAccount string
		err := withSpinner(fmt.Sprintf("Checking billing for project %s...", projectID), func() error {
			checkCmd := exec.CommandContext(cmd.Context(), "gcloud", "billing", "projects", "describe", projectID, "--format=value(billingAccountName)")
			output, _ := checkCmd.Output()
			billingAccount = strings.TrimSpace(string(output))
			return nil
		})
		if err != nil {
			return err
		}

		if billingAccount == "" {
			printWarning("No billing account linked to this project.")
			fmt.Println("   Billing is required to enable Secret Manager API.")

			// Get available billing accounts
			accounts, _ := gcp.GetBillingAccounts()
			if len(accounts) > 0 {
				var options []huh.Option[string]
				for _, acc := range accounts {
					id := strings.TrimPrefix(acc.Name, "billingAccounts/")
					label := fmt.Sprintf("%s (%s)", acc.DisplayName, id)
					options = append(options, huh.NewOption(label, id))
				}
				options = append(options, huh.NewOption("Skip (link billing manually later)", "skip"))

				var billingID string
				err := huh.NewSelect[string]().
					Title("Select a billing account").
					Options(options...).
					Value(&billingID).
					Run()
				if err != nil {
					return err
				}

				if billingID != "skip" {
					fmt.Printf("Linking billing account %s...\n", billingID)
					linkCmd := exec.CommandContext(cmd.Context(), "gcloud", "billing", "projects", "link",
						projectID, "--billing-account="+billingID)
					if output, err := linkCmd.CombinedOutput(); err != nil {
						printWarning("Could not link billing: %s", string(output))
						fmt.Println("   You may need to link billing manually.")
					} else {
						printSuccess("Billing account linked")
					}
				}
			} else {
				fmt.Println("   No billing accounts found. Please link billing manually at:")
				fmt.Printf("   https://console.cloud.google.com/billing/linkedaccount?project=%s\n", projectID)
			}
		} else {
			printSuccess("Billing enabled (%s)", billingAccount)
		}

		// Enable Secret Manager API
		var enableOut []byte
		var enableErr error
		err = withSpinner(fmt.Sprintf("Enabling Secret Manager API for project %s...", projectID), func() error {
			enableCmd := exec.CommandContext(cmd.Context(), "gcloud", "services", "enable",
				"secretmanager.googleapis.com", "--project", projectID)
			enableOut, enableErr = enableCmd.CombinedOutput()
			return nil
		})
		if err != nil {
			return err
		}
		if enableErr != nil {
			printWarning("Could not enable Secret Manager API: %s", string(enableOut))
			fmt.Println("   You may need to enable it manually at:")
			fmt.Printf("   https://console.cloud.google.com/apis/library/secretmanager.googleapis.com?project=%s\n", projectID)
		} else {
			printSuccess("Secret Manager API enabled")
		}
	}

	controllerNS := "kube-system"
	controllerName := "sealed-secrets"

	// Interactive prompts for controller
	{
		fmt.Println()
		printStep(2, 7, "Controller Discovery")
		fmt.Println()

		// Attempt to discover controller
		var discoveredNS, discoveredName string
		var discoverErr error
		err := withSpinner("Scanning cluster for SealedSecrets controller...", func() error {
			discoveredNS, discoveredName, discoverErr = discoverController()
			return nil
		})
		if err != nil {
			return err
		}
		if discoverErr == nil && discoveredNS != "" {
			printSuccess("Found controller in namespace '%s' (service: '%s')", discoveredNS, discoveredName)
			controllerNS = discoveredNS
			controllerName = discoveredName
		} else {
			// Fallback to selection if not automatically found
			namespaces, err := getNamespaces()
			if err == nil && len(namespaces) > 0 {
				var nsOption string
				err = huh.NewSelect[string]().
					Title("Controller Namespace").
					Description("Select the namespace where the SealedSecrets controller is running").
					Options(huh.NewOptions(namespaces...)...).
					Value(&nsOption).
					Run()
				if err != nil {
					return err
				}
				controllerNS = nsOption
			} else {
				// Manual entry backup
				err = huh.NewInput().
					Title("Controller Namespace").
					Description("Could not list namespaces. Enter manually (e.g. kube-system)").
					Value(&controllerNS).
					Run()
				if err != nil {
					return err
				}
			}

			// Service name prompt
			err = huh.NewInput().
				Title("Controller Service Name").
				Description("Service name of the Sealed Secrets controller").
				Value(&controllerName).
				Run()
			if err != nil {
				return err
			}
		}
	}

	// Create directories
	if err := os.MkdirAll(metadataDir, 0o755); err != nil {
		return fmt.Errorf("create metadata directory: %w", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}

	// Generate config
	config := generateConfig(projectID, controllerNS, controllerName)

	if dryRun {
		fmt.Println("Would create config:")
		fmt.Println(config)
		return nil
	}

	// Write config atomically
	writer := files.NewAtomicWriter()
	if err := writer.Write(configFile, []byte(config)); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Create .gitkeep in metadata
	gitkeepPath := filepath.Join(metadataDir, ".gitkeep")
	if err := os.WriteFile(gitkeepPath, []byte{}, 0o644); err != nil {
		return fmt.Errorf("write .gitkeep: %w", err)
	}

	printSuccess("Created %s", configFile)
	printSuccess("Created %s", metadataDir)

	// Fetch certificate from cluster
	certPath := filepath.Join(keysDir, "pub-cert.pem")
	fmt.Println()
	printStep(3, 7, "Certificate Fetch")
	fmt.Println()

	var certOutput []byte
	var certErr error
	if err := withSpinner("Fetching certificate from controller...", func() error {
		c := exec.Command("kubeseal",
			"--controller-name="+controllerName,
			"--controller-namespace="+controllerNS,
			"--fetch-cert")
		certOutput, certErr = c.Output()
		return nil
	}); err != nil {
		return err
	}

	if certErr != nil {
		printWarning("Could not fetch certificate from cluster.")
		fmt.Println("   This might mean:")
		fmt.Println("   - kubeseal is not installed")
		fmt.Println("   - kubectl is not configured")
		fmt.Println("   - The Sealed Secrets controller is not running")
		fmt.Println()
		fmt.Println("   You can fetch it manually later:")
		fmt.Printf("     kubeseal --controller-name=%s --controller-namespace=%s --fetch-cert > %s\n",
			controllerName, controllerNS, filepath.Join("keys", "pub-cert.pem"))
		fmt.Println()

		// Create placeholder
		placeholder := "# Certificate could not be fetched automatically.\n# Run: kubeseal --fetch-cert > keys/pub-cert.pem\n"
		os.WriteFile(certPath, []byte(placeholder), 0o644)
	} else {
		if err := os.WriteFile(certPath, certOutput, 0o644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		printSuccess("Saved certificate to %s", certPath)
	}

	// Run discover
	if certErr == nil {
		fmt.Println()
		printStep(4, 7, "Secret Discovery")
		fmt.Println()
		fmt.Println("Looking for existing SealedSecrets...")
		fmt.Println()

		// Call discover command (call run directly to avoid re-parsing root args)
		discoverNonInteractive = false
		if err := runDiscover(cmd, []string{}); err != nil {
			// Don't fail init if discover has issues
			fmt.Printf("Note: discover encountered an issue: %v\n", err)
			fmt.Println("You can run 'waxseal discover' later to find existing SealedSecrets.")
		} else {
			// Check if there are secrets to bootstrap
			metadataFiles, _ := filepath.Glob(filepath.Join(metadataDir, "*.yaml"))
			if len(metadataFiles) > 0 {
				fmt.Println()
				var doBootstrap bool
				err := huh.NewConfirm().
					Title("Sync discovered secrets to GSM?").
					Description("This will read secrets from your cluster and push them to Google Secret Manager.").
					Value(&doBootstrap).
					Run()
				if err == nil && doBootstrap {
					fmt.Println()
					printStep(6, 7, "Bootstrap to GSM")
					fmt.Println()
					fmt.Println("Syncing secrets to GSM...")
					for _, mf := range metadataFiles {
						shortName := strings.TrimSuffix(filepath.Base(mf), ".yaml")
						if shortName == ".gitkeep" {
							continue
						}
						fmt.Printf("\nBootstrapping %s...\n", shortName)
						if err := runBootstrap(cmd, []string{shortName}); err != nil {
							printWarning("Could not bootstrap %s: %v", shortName, err)
							fmt.Println("   You can run 'waxseal bootstrap " + shortName + "' later.")
						}
					}
				}
			}
		}
	}

	// Offer reminders setup
	{
		fmt.Println()
		printStep(7, 7, "Expiration Reminders (Optional)")
		fmt.Println()
		fmt.Println("WaxSeal can create automatic reminders for secrets with expiry dates.")
		fmt.Println()
		fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    REMINDER PROVIDERS                         ║")
		fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
		fmt.Println("║  📋 GOOGLE TASKS (Recommended)                                ║")
		fmt.Println("║     • Creates tasks in your Google Tasks list                 ║")
		fmt.Println("║     • Tasks with due dates auto-appear in Google Calendar     ║")
		fmt.Println("║     • Simpler setup, no extra calendar clutter                ║")
		fmt.Println("║                                                               ║")
		fmt.Println("║  📅 GOOGLE CALENDAR                                           ║")
		fmt.Println("║     • Creates calendar events directly                        ║")
		fmt.Println("║     • More visible, with email notifications                  ║")
		fmt.Println("║     • Requires Calendar API and calendar selection            ║")
		fmt.Println("║                                                               ║")
		fmt.Println("║  Both require Application Default Credentials (gcloud auth)  ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		fmt.Println()

		// Provider selection
		var reminderChoice string
		err := huh.NewSelect[string]().
			Title("Which reminder provider(s) would you like to use?").
			Options(
				huh.NewOption("📋 Google Tasks only (recommended)", "tasks"),
				huh.NewOption("📅 Google Calendar only", "calendar"),
				huh.NewOption("🔔 Both Tasks and Calendar", "both"),
				huh.NewOption("⏭️  Skip reminders for now", "none"),
			).
			Value(&reminderChoice).
			Run()
		if err != nil {
			return err
		}

		if reminderChoice == "none" {
			fmt.Println("Skipping reminders setup. You can configure later with 'waxseal reminders setup'.")
		} else {
			// Collect lead time days (common to all providers)
			leadTimeStr := "30, 7, 1"
			err = huh.NewInput().
				Title("Lead Time Days").
				Description("Comma-separated days before expiry to create reminders (e.g., '30, 7, 1')").
				Value(&leadTimeStr).
				Validate(func(s string) error {
					if len(parseReminderIntList(s)) == 0 {
						return fmt.Errorf("must provide at least one day")
					}
					return nil
				}).
				Run()
			if err != nil {
				return err
			}

			// Tasks configuration
			tasklistID := "@default"
			if reminderChoice == "tasks" || reminderChoice == "both" {
				fmt.Println()
				fmt.Println("📋 Google Tasks Configuration")
				fmt.Println("   Using the default task list (@default) means tasks appear in your")
				fmt.Println("   primary Google Tasks list and auto-show in Calendar.")
				fmt.Println()

				var customTasklist bool
				err = huh.NewConfirm().
					Title("Use a custom task list?").
					Description("Default (@default) is recommended for most users").
					Value(&customTasklist).
					Affirmative("Yes, specify custom").
					Negative("No, use default").
					Run()
				if err != nil {
					return err
				}

				if customTasklist {
					err = huh.NewInput().
						Title("Task List ID").
						Description("Enter your task list ID (find via Tasks API or Google Tasks settings)").
						Value(&tasklistID).
						Run()
					if err != nil {
						return err
					}
				}
			}

			// Calendar configuration
			calendarID := "primary"
			if reminderChoice == "calendar" || reminderChoice == "both" {
				fmt.Println()
				fmt.Println("📅 Google Calendar Configuration")
				fmt.Println("   'primary' uses the calendar of the authenticated Google account.")
				fmt.Println("   You can also specify a shared calendar's email address.")
				fmt.Println()

				err = huh.NewInput().
					Title("Calendar ID").
					Description("Use 'primary' or a calendar email (e.g., team@group.calendar.google.com)").
					Value(&calendarID).
					Run()
				if err != nil {
					return err
				}
			}

			// Build and display config snippet
			reminderConfig := buildReminderConfig(reminderChoice, tasklistID, calendarID, leadTimeStr)
			fmt.Println()
			fmt.Println("Generated reminders configuration:")
			fmt.Println("┌─────────────────────────────────────────────────────")
			for _, line := range strings.Split(reminderConfig, "\n") {
				fmt.Printf("│ %s\n", line)
			}
			fmt.Println("└─────────────────────────────────────────────────────")
			fmt.Println()

			// Update config
			var updateConfig bool
			err = huh.NewConfirm().
				Title("Add this to your config?").
				Value(&updateConfig).
				Run()
			if err != nil {
				return err
			}

			if updateConfig {
				configFile := filepath.Join(repoPath, ".waxseal", "config.yaml")
				existingConfig, err := os.ReadFile(configFile)
				if err != nil {
					printWarning("Could not read config: %v", err)
				} else if strings.Contains(string(existingConfig), "reminders:") {
					printWarning("Config already contains reminders section. Update manually.")
				} else {
					newConfig := string(existingConfig) + "\n" + reminderConfig
					if err := os.WriteFile(configFile, []byte(newConfig), 0o644); err != nil {
						printWarning("Could not update config: %v", err)
					} else {
						printSuccess("Reminders configuration added to config")
					}
				}
			} else {
				fmt.Println("Config not updated. Add the snippet to .waxseal/config.yaml manually.")
			}
		}
	}

	fmt.Println()
	printSuccess("WaxSeal initialization complete!")
	fmt.Println()
	fmt.Println("Next: Run 'waxseal reseal --all' to sync secrets from GSM to your SealedSecrets.")

	return nil
}

func generateConfig(projectID, controllerNS, controllerName string) string {
	return fmt.Sprintf(`# waxseal configuration
# Generated by waxseal setup

version: "1"

store:
  kind: gsm
  projectId: %s
  # defaultReplication: automatic

controller:
  namespace: %s
  serviceName: %s

cert:
  repoCertPath: keys/pub-cert.pem
  verifyAgainstCluster: true

discovery:
  includeGlobs:
    - "apps/**/*.yaml"
    - "**/*sealed*.yaml"
  excludeGlobs:
    - "**/kustomization.yaml"
    - "**/*.tmpl.yaml"

# reminders:
#   enabled: false
#   provider: google-calendar
#   calendarId: primary
#   leadTimeDays: [30, 7, 1]
#   auth:
#     kind: adc
`, projectID, controllerNS, controllerName)
}

func confirmOverwrite() bool {
	var overwrite bool
	err := huh.NewConfirm().
		Title("Configuration file already exists. Overwrite?").
		Value(&overwrite).
		Run()
	if err != nil {
		return false
	}
	return overwrite
}

// discoverController tries to find the SealedSecrets controller in the cluster
func discoverController() (string, string, error) {
	// 1. Try to find pod by label
	// Standard helm chart uses app.kubernetes.io/name=sealed-secrets
	cmd := exec.Command("kubectl", "get", "pods", "-A",
		"-l", "app.kubernetes.io/name=sealed-secrets",
		"-o", "jsonpath={.items[0].metadata.namespace}/{.items[0].metadata.name}")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		parts := strings.Split(string(output), "/")
		if len(parts) >= 1 {
			// Found namespace, now guess service name
			// Usually: sealed-secrets-controller, sealed-secrets, or similar
			ns := parts[0]
			svcName := "sealed-secrets-controller" // standard default

			// Verify service exists
			check := exec.Command("kubectl", "get", "svc", "-n", ns, svcName)
			if err := check.Run(); err != nil {
				// Try alternate name
				svcName = "sealed-secrets"
				check = exec.Command("kubectl", "get", "svc", "-n", ns, svcName)
				if err := check.Run(); err != nil {
					return "", "", fmt.Errorf("service not found")
				}
			}
			return ns, svcName, nil
		}
	}
	return "", "", fmt.Errorf("controller not found")
}

// getNamespaces lists all namespaces in the cluster
func getNamespaces() ([]string, error) {
	cmd := exec.Command("kubectl", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), " "), nil
}

// parseReminderIntList parses a comma-separated list of integers.
func parseReminderIntList(s string) []int {
	s = strings.Trim(s, "[]")
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := 0
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				n = -1
				break
			}
		}
		if n >= 0 {
			result = append(result, n)
		}
	}
	return result
}

// buildReminderConfig generates the reminders config section.
func buildReminderConfig(provider, tasklistID, calendarID, leadTimeStr string) string {
	var sb strings.Builder
	sb.WriteString("reminders:\n")
	sb.WriteString("  enabled: true\n")
	sb.WriteString(fmt.Sprintf("  provider: %s\n", provider))

	if provider == "tasks" || provider == "both" {
		if tasklistID != "@default" {
			sb.WriteString(fmt.Sprintf("  tasklistId: \"%s\"\n", tasklistID))
		}
		// @default is the default, so no need to write it
	}

	if provider == "calendar" || provider == "both" {
		sb.WriteString(fmt.Sprintf("  calendarId: %s\n", calendarID))
	}

	// Format lead time days
	days := parseReminderIntList(leadTimeStr)
	var dayStrs []string
	for _, d := range days {
		dayStrs = append(dayStrs, fmt.Sprintf("%d", d))
	}
	sb.WriteString(fmt.Sprintf("  leadTimeDays: [%s]\n", strings.Join(dayStrs, ", ")))
	sb.WriteString("  auth:\n")
	sb.WriteString("    kind: adc\n")

	return sb.String()
}
