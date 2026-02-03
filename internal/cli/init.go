package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().BoolVar(&initNonInteractive, "non-interactive", false, "Run without prompts")
	initCmd.Flags().StringVar(&initProjectID, "project-id", "", "GCP Project ID for Secret Manager")
	initCmd.Flags().StringVar(&initControllerNS, "controller-namespace", "kube-system", "Sealed Secrets controller namespace")
	initCmd.Flags().StringVar(&initControllerName, "controller-name", "sealed-secrets", "Sealed Secrets controller service name")
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
		fmt.Print("Overwrite? [y/N]: ")
		if !confirmOverwrite() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Get project ID
	projectID := initProjectID
	if projectID == "" && !initNonInteractive {
		// Welcome message
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    Welcome to WaxSeal                        ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("WaxSeal syncs your Kubernetes SealedSecrets with Google Secret Manager.")
		fmt.Println("Secret values are stored in GCP - only encrypted ciphertext goes in Git.")
		fmt.Println()

		// Project setup choice
		var setupChoice string
		err := huh.NewSelect[string]().
			Title("How do you want to set up GCP?").
			Options(
				huh.NewOption("Use an existing GCP project", "existing"),
				huh.NewOption("Create a new GCP project (requires gcloud CLI)", "create"),
			).
			Value(&setupChoice).
			Run()
		if err != nil {
			return err
		}

		if setupChoice == "create" {
			fmt.Println()
			fmt.Println("To create a new GCP project, you'll need:")
			fmt.Println("  • gcloud CLI installed and authenticated (gcloud auth login)")
			fmt.Println("  • A GCP billing account ID (find at console.cloud.google.com/billing)")
			fmt.Println()
			fmt.Println("Run:")
			fmt.Println("  waxseal gcp bootstrap --project-id=YOUR-PROJECT --create-project --billing-account-id=BILLING-ID")
			fmt.Println()
			fmt.Println("This will create the project, enable Secret Manager API, and set up a service account.")
			fmt.Println()
			fmt.Println("Then re-run 'waxseal init' with your new project ID.")
			return nil
		}

		// Get project ID with huh input
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
	if projectID == "" && initNonInteractive {
		return fmt.Errorf("--project-id is required in non-interactive mode")
	}

	controllerNS := initControllerNS
	controllerName := initControllerName

	// Interactive prompts for controller
	if !initNonInteractive {
		err := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Controller namespace").
					Description("Kubernetes namespace where Sealed Secrets controller runs").
					Value(&controllerNS),
				huh.NewInput().
					Title("Controller service name").
					Description("Service name of the Sealed Secrets controller").
					Value(&controllerName),
			),
		).Run()
		if err != nil {
			return err
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

func prompt(message string) string {
	fmt.Print(message)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func confirmOverwrite() bool {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}
