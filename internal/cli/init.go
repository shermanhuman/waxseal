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
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize waxseal in a GitOps repository",
	Long: `Initialize waxseal configuration in the current repository.

This command creates:
  - .waxseal/config.yaml - Main configuration file
  - .waxseal/metadata/   - Directory for secret metadata
  - keys/pub-cert.pem    - Placeholder for controller certificate

Interactive mode prompts for:
  - GCP Project ID for Secret Manager
  - Controller namespace and name

Use --non-interactive with required flags for CI/automation.`,
	RunE: runInit,
}

var (
	initNonInteractive bool
	initProjectID      string
	initControllerNS   string
	initControllerName string
	initSkipReminders  bool
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().BoolVar(&initNonInteractive, "non-interactive", false, "Run without prompts")
	initCmd.Flags().StringVar(&initProjectID, "project-id", "", "GCP Project ID for Secret Manager")
	initCmd.Flags().StringVar(&initControllerNS, "controller-namespace", "kube-system", "Sealed Secrets controller namespace")
	initCmd.Flags().StringVar(&initControllerName, "controller-name", "sealed-secrets", "Sealed Secrets controller service name")
	initCmd.Flags().BoolVar(&initSkipReminders, "skip-reminders", false, "Skip the calendar reminders setup prompt")
}

func runInit(cmd *cobra.Command, args []string) error {
	waxsealDir := filepath.Join(repoPath, ".waxseal")
	metadataDir := filepath.Join(waxsealDir, "metadata")
	keysDir := filepath.Join(repoPath, "keys")
	configFile := filepath.Join(waxsealDir, "config.yaml")

	// Check if this looks like a project root
	if !initNonInteractive {
		gitDir := filepath.Join(repoPath, ".git")
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			fmt.Println()
			fmt.Println("⚠️  Warning: No .git folder found in this directory.")
			fmt.Println("   WaxSeal should be initialized in the root of your GitOps repository.")
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
				fmt.Println("Aborted. Please cd to your repository root and run 'waxseal init' again.")
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

	// Welcome message (interactive only)
	if !initNonInteractive {
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    Welcome to WaxSeal                        ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("WaxSeal syncs your Kubernetes SealedSecrets with Google Secret Manager.")
		fmt.Println("Secret values are stored in GCP - only encrypted ciphertext goes in Git.")
		fmt.Println()
	}

	// Handle GCP setup
	projectID := initProjectID
	if projectID == "" && !initNonInteractive {
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
			if err := CheckGcloudInstalled(); err != nil {
				return err
			}

			// Ensure auth before fetching billing accounts
			if err := EnsureGcloudAuth(); err != nil {
				return err
			}

			// 0. Resolve Organization (optional)
			var orgID string
			orgs, _ := GetOrganizations()
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

			// 1. Get Project ID
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

			// 2. Resolve Billing Account
			var billingID string

			// Try to fetch available accounts
			accounts, _ := GetBillingAccounts()
			var options []huh.Option[string]
			for _, acc := range accounts {
				if acc.Open {
					id := strings.TrimPrefix(acc.Name, "billingAccounts/")
					label := fmt.Sprintf("%s (%s)", acc.DisplayName, id)
					options = append(options, huh.NewOption(label, id))
				}
			}
			options = append(options, huh.NewOption("Enter manually...", "manual"))

			// If we found accounts, let user choose
			if len(options) > 1 {
				var choice string
				err = huh.NewSelect[string]().
					Title("Billing Account").
					Options(options...).
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

			// Setup bootstrap flags
			gcpProjectID = projectID
			gcpCreateProject = true
			gcpBillingAccountID = billingID
			gcpOrgID = orgID

			// Run bootstrap (this now handles Auth and ADC proactively)
			if err := runGCPBootstrap(cmd, nil); err != nil {
				return fmt.Errorf("bootstrap failed: %w", err)
			}

			fmt.Println()
			fmt.Println("✓ GCP Project created and bootstrapped.")
			fmt.Println("Proceeding with WaxSeal initialization...")
			fmt.Println()
		} else {
			// Ensure authed even for existing project since discover/add will need it
			if err := EnsureGcloudAuth(); err != nil {
				return err
			}
			if err := EnsureGcloudADC(); err != nil {
				return err
			}

			// Try to list projects
			projects, _ := GetProjects()
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
	if projectID == "" && initNonInteractive {
		return fmt.Errorf("--project-id is required in non-interactive mode")
	}

	controllerNS := initControllerNS
	controllerName := initControllerName

	// Interactive prompts for controller
	if !initNonInteractive {
		// Attempt to discover controller
		fmt.Println("Scanning cluster for SealedSecrets controller...")
		discoveredNS, discoveredName, err := discoverController()
		if err == nil && discoveredNS != "" {
			fmt.Printf("✓ Found controller in namespace '%s' (service: '%s')\n", discoveredNS, discoveredName)
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

	fmt.Printf("✓ Created %s\n", configFile)
	fmt.Printf("✓ Created %s\n", metadataDir)

	// Fetch certificate from cluster
	certPath := filepath.Join(keysDir, "pub-cert.pem")
	fmt.Println()
	fmt.Println("Fetching certificate from Sealed Secrets controller...")

	certCmd := exec.Command("kubeseal",
		"--controller-name="+controllerName,
		"--controller-namespace="+controllerNS,
		"--fetch-cert")
	certOutput, certErr := certCmd.Output()

	if certErr != nil {
		fmt.Println("⚠️  Could not fetch certificate from cluster.")
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
		fmt.Printf("✓ Saved certificate to %s\n", certPath)
	}

	// Run discover if interactive
	if !initNonInteractive && certErr == nil {
		fmt.Println()
		fmt.Println("Looking for existing SealedSecrets...")
		fmt.Println()

		// Call discover command
		discoverCmd.SetArgs([]string{})
		if err := discoverCmd.Execute(); err != nil {
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
					fmt.Println("Syncing secrets to GSM...")
					for _, mf := range metadataFiles {
						shortName := strings.TrimSuffix(filepath.Base(mf), ".yaml")
						if shortName == ".gitkeep" {
							continue
						}
						fmt.Printf("\nBootstrapping %s...\n", shortName)
						bootstrapCmd.SetArgs([]string{shortName})
						if err := bootstrapCmd.Execute(); err != nil {
							fmt.Printf("⚠️  Could not bootstrap %s: %v\n", shortName, err)
							fmt.Println("   You can run 'waxseal bootstrap " + shortName + "' later.")
						}
					}
				}
			}
		}
	}

	// Offer reminders setup
	if !initNonInteractive && !initSkipReminders {
		fmt.Println()
		var setupReminders bool
		err := huh.NewConfirm().
			Title("Set up expiration reminders?").
			Description("Create Google Calendar events for secret rotation reminders.\nRequires Calendar API enabled in your GCP project.").
			Value(&setupReminders).
			Run()
		if err == nil && setupReminders {
			fmt.Println()
			fmt.Println("Running reminders setup...")
			remindersSetupCmd.SetArgs([]string{})
			if err := remindersSetupCmd.Execute(); err != nil {
				fmt.Printf("⚠️  Reminders setup failed: %v\n", err)
				fmt.Println("   You can run 'waxseal reminders setup' later.")
			}
		}
	}

	fmt.Println()
	fmt.Println("✓ WaxSeal initialization complete!")
	fmt.Println()
	fmt.Println("Next: Run 'waxseal reseal --all' to sync secrets from GSM to your SealedSecrets.")

	return nil
}

func generateConfig(projectID, controllerNS, controllerName string) string {
	return fmt.Sprintf(`# waxseal configuration
# Generated by waxseal init

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
