package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shermanhuman/waxseal/internal/config"
	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/reminders"
	"github.com/spf13/cobra"
)

var remindersCmd = &cobra.Command{
	Use:   "reminders",
	Short: "Manage expiry reminders in Google Calendar",
	Long: `Manage calendar reminders for secret expiration dates.

Subcommands:
  sync    Create/update calendar events for expiring secrets
  clear   Remove all calendar events for a secret

Requires:
  - reminders.enabled: true in config
  - Google Calendar API access via Application Default Credentials`,
}

var remindersSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync expiry reminders to calendar",
	Long: `Create or update calendar events for secrets with expiry dates.

Creates reminder events at configured lead times (e.g., 30, 7, 1 days before expiry).
Events are updated if they already exist (idempotent).`,
	RunE: runRemindersSync,
}

var remindersClearCmd = &cobra.Command{
	Use:   "clear <shortName>",
	Short: "Clear reminders for a secret",
	Long:  `Remove all calendar events associated with a secret (e.g., after retirement).`,
	Args:  cobra.ExactArgs(1),
	RunE:  runRemindersClear,
}

func init() {
	rootCmd.AddCommand(remindersCmd)
	remindersCmd.AddCommand(remindersSyncCmd)
	remindersCmd.AddCommand(remindersClearCmd)
}

func runRemindersSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Check if reminders are enabled
	if cfg.Reminders == nil || !cfg.Reminders.Enabled {
		fmt.Println("Reminders are not enabled in config.")
		fmt.Println("Add the following to your config to enable:")
		fmt.Print(`
reminders:
  enabled: true
  provider: google-calendar
  calendarId: primary
  leadTimeDays: [30, 7, 1]
  auth:
    kind: adc
`)
		return nil
	}

	// Load all metadata
	secrets, err := loadAllMetadata()
	if err != nil {
		return err
	}

	// Filter to secrets with expiry
	var expiringSecrets []*core.SecretMetadata
	for _, s := range secrets {
		if hasExpiry(s) {
			expiringSecrets = append(expiringSecrets, s)
		}
	}

	if len(expiringSecrets) == 0 {
		fmt.Println("No secrets with expiry dates found.")
		return nil
	}

	fmt.Printf("Found %d secrets with expiry dates\n", len(expiringSecrets))

	if dryRun {
		for _, s := range expiringSecrets {
			for _, k := range s.Keys {
				if k.Expiry != nil && k.Expiry.ExpiresAt != "" {
					fmt.Printf("  %s/%s expires %s\n", s.ShortName, k.KeyName, k.Expiry.ExpiresAt)
				}
			}
		}
		fmt.Println("\n[DRY RUN] Would sync reminders to calendar")
		return nil
	}

	// Create provider
	provider, err := reminders.NewGoogleCalendarProvider(
		ctx,
		cfg.Reminders.CalendarID,
		cfg.Reminders.LeadTimeDays,
	)
	if err != nil {
		return fmt.Errorf("create calendar provider: %w", err)
	}

	// Sync
	result, err := provider.SyncReminders(ctx, expiringSecrets)
	if err != nil {
		return fmt.Errorf("sync reminders: %w", err)
	}

	fmt.Printf("✓ Created: %d, Updated: %d, Skipped: %d\n",
		result.Created, result.Updated, result.Skipped)

	if len(result.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\nErrors:\n")
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", e)
		}
	}

	return nil
}

func runRemindersClear(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	shortName := args[0]

	// Load config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Reminders == nil || !cfg.Reminders.Enabled {
		return fmt.Errorf("reminders not enabled in config")
	}

	if dryRun {
		fmt.Printf("[DRY RUN] Would clear reminders for %s\n", shortName)
		return nil
	}

	provider, err := reminders.NewGoogleCalendarProvider(
		ctx,
		cfg.Reminders.CalendarID,
		cfg.Reminders.LeadTimeDays,
	)
	if err != nil {
		return fmt.Errorf("create calendar provider: %w", err)
	}

	if err := provider.DeleteReminders(ctx, shortName); err != nil {
		return fmt.Errorf("delete reminders: %w", err)
	}

	fmt.Printf("✓ Cleared reminders for %s\n", shortName)
	return nil
}

func loadAllMetadata() ([]*core.SecretMetadata, error) {
	metadataDir := filepath.Join(repoPath, ".waxseal", "metadata")
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("metadata directory not found: %s", metadataDir)
		}
		return nil, fmt.Errorf("read metadata directory: %w", err)
	}

	var secrets []*core.SecretMetadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(metadataDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		m, err := core.ParseMetadata(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		secrets = append(secrets, m)
	}

	return secrets, nil
}

func hasExpiry(s *core.SecretMetadata) bool {
	for _, k := range s.Keys {
		if k.Expiry != nil && k.Expiry.ExpiresAt != "" {
			return true
		}
	}
	return false
}
