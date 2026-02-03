package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
  list    List secrets with upcoming expirations
  sync    Create/update calendar events for expiring secrets
  clear   Remove all calendar events for a secret
  setup   Configure reminder settings

Requires:
  - reminders.enabled: true in config (except for list and setup)
  - Google Calendar API access via Application Default Credentials`,
}

var remindersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List upcoming expirations",
	Long: `List all secrets with expiry dates, sorted by expiration time.

Default window is 90 days from now. Use --days to adjust.`,
	RunE: runRemindersList,
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

var remindersSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure reminder settings",
	Long: `Interactive setup wizard for configuring calendar reminders.

This will guide you through:
  - Enabling reminders in config
  - Choosing a calendar
  - Setting lead time days
  - Verifying API access`,
	RunE: runRemindersSetup,
}

var remindersListDays int

func init() {
	rootCmd.AddCommand(remindersCmd)
	remindersCmd.AddCommand(remindersListCmd)
	remindersCmd.AddCommand(remindersSyncCmd)
	remindersCmd.AddCommand(remindersClearCmd)
	remindersCmd.AddCommand(remindersSetupCmd)

	remindersListCmd.Flags().IntVar(&remindersListDays, "days", 90, "Show expirations within this many days")
}

func runRemindersSync(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

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
	ctx := cmd.Context()
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

func runRemindersList(cmd *cobra.Command, args []string) error {
	secrets, err := loadAllMetadata()
	if err != nil {
		return err
	}

	// Collect all expiring keys
	type expiringKey struct {
		shortName string
		keyName   string
		expiresAt string
		daysUntil int
		expired   bool
	}

	var expiring []expiringKey
	now := time.Now()
	threshold := now.AddDate(0, 0, remindersListDays)

	for _, s := range secrets {
		if s.IsRetired() {
			continue
		}
		for _, k := range s.Keys {
			if k.Expiry != nil && k.Expiry.ExpiresAt != "" {
				exp, err := time.Parse(time.RFC3339, k.Expiry.ExpiresAt)
				if err != nil {
					continue
				}

				// Filter by threshold
				if exp.Before(threshold) {
					days := int(exp.Sub(now).Hours() / 24)
					expiring = append(expiring, expiringKey{
						shortName: s.ShortName,
						keyName:   k.KeyName,
						expiresAt: k.Expiry.ExpiresAt,
						daysUntil: days,
						expired:   exp.Before(now),
					})
				}
			}
		}
	}

	if len(expiring) == 0 {
		fmt.Printf("No secrets expiring within %d days.\n", remindersListDays)
		return nil
	}

	// Sort by expiry date (inline bubble sort)
	for i := 0; i < len(expiring); i++ {
		for j := i + 1; j < len(expiring); j++ {
			if expiring[i].expiresAt > expiring[j].expiresAt {
				expiring[i], expiring[j] = expiring[j], expiring[i]
			}
		}
	}

	fmt.Printf("Secrets expiring within %d days:\n\n", remindersListDays)
	fmt.Printf("%-25s %-20s %-12s %s\n", "SECRET", "KEY", "DAYS", "EXPIRES")
	fmt.Printf("%-25s %-20s %-12s %s\n", strings.Repeat("-", 25), strings.Repeat("-", 20), strings.Repeat("-", 12), strings.Repeat("-", 25))

	for _, ek := range expiring {
		status := fmt.Sprintf("%d days", ek.daysUntil)
		if ek.expired {
			status = "EXPIRED"
		} else if ek.daysUntil == 0 {
			status = "TODAY"
		} else if ek.daysUntil == 1 {
			status = "1 day"
		}

		fmt.Printf("%-25s %-20s %-12s %s\n", ek.shortName, ek.keyName, status, ek.expiresAt[:10])
	}

	// Summary
	expiredCount := 0
	soonCount := 0
	for _, ek := range expiring {
		if ek.expired {
			expiredCount++
		} else if ek.daysUntil <= 7 {
			soonCount++
		}
	}

	fmt.Println()
	if expiredCount > 0 {
		fmt.Printf("⚠ %d expired keys require immediate attention\n", expiredCount)
	}
	if soonCount > 0 {
		fmt.Printf("⚠ %d keys expire within 7 days\n", soonCount)
	}

	return nil
}

func runRemindersSetup(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("WaxSeal Reminders Setup")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Println("This wizard will configure Google Calendar reminders for secret expiration.")
	fmt.Println()

	// Check for existing config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	_, err := os.Stat(configFile)
	if os.IsNotExist(err) {
		fmt.Println("No config file found. Run 'waxseal init' first.")
		return nil
	}

	fmt.Println("Prerequisites:")
	fmt.Println("  1. Enable Google Calendar API in your GCP project")
	fmt.Println("  2. Set up Application Default Credentials:")
	fmt.Println("     gcloud auth application-default login \\")
	fmt.Println("       --scopes https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/calendar.events")
	fmt.Println()

	fmt.Print("Continue? [y/N]: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	if input != "y" && input != "yes" {
		fmt.Println("Setup cancelled.")
		return nil
	}

	fmt.Println()

	// Calendar ID
	fmt.Println("Choose a calendar:")
	fmt.Println("  - 'primary' for your main calendar")
	fmt.Println("  - Or enter a specific calendar ID")
	fmt.Print("Calendar ID [primary]: ")
	calendarID, _ := reader.ReadString('\n')
	calendarID = strings.TrimSpace(calendarID)
	if calendarID == "" {
		calendarID = "primary"
	}

	// Lead time days
	fmt.Println()
	fmt.Println("Lead time days (when to create reminders before expiry)")
	fmt.Print("Lead time days [30,7,1]: ")
	leadTimeInput, _ := reader.ReadString('\n')
	leadTimeInput = strings.TrimSpace(leadTimeInput)

	leadTimeDays := []int{30, 7, 1}
	if leadTimeInput != "" {
		leadTimeDays = parseIntList(leadTimeInput)
		if len(leadTimeDays) == 0 {
			leadTimeDays = []int{30, 7, 1}
		}
	}

	// Build config snippet
	fmt.Println()
	fmt.Println("Add this to your .waxseal/config.yaml:")
	fmt.Println()
	fmt.Printf("reminders:\n")
	fmt.Printf("  enabled: true\n")
	fmt.Printf("  provider: google-calendar\n")
	fmt.Printf("  calendarId: %s\n", calendarID)
	fmt.Printf("  leadTimeDays: [%s]\n", formatIntList(leadTimeDays))
	fmt.Printf("  auth:\n")
	fmt.Printf("    kind: adc\n")
	fmt.Println()

	if dryRun {
		fmt.Println("[DRY RUN] Would update config file")
		return nil
	}

	fmt.Print("Would you like to update the config file automatically? [y/N]: ")
	updateInput, _ := reader.ReadString('\n')
	updateInput = strings.TrimSpace(strings.ToLower(updateInput))
	if updateInput != "y" && updateInput != "yes" {
		fmt.Println("Config not updated. Add the snippet manually.")
		return nil
	}

	// Read existing config
	existingConfig, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Check if reminders already exists
	if strings.Contains(string(existingConfig), "reminders:") {
		fmt.Println("Config already contains reminders section. Update manually.")
		return nil
	}

	// Append reminders config
	remindersConfig := fmt.Sprintf(`
reminders:
  enabled: true
  provider: google-calendar
  calendarId: %s
  leadTimeDays: [%s]
  auth:
    kind: adc
`, calendarID, formatIntList(leadTimeDays))

	newConfig := string(existingConfig) + remindersConfig
	if err := os.WriteFile(configFile, []byte(newConfig), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Println("✓ Config updated successfully")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'waxseal reminders sync' to create calendar events")
	fmt.Println("  2. Check your calendar to verify events were created")

	return nil
}

func parseIntList(s string) []int {
	s = strings.Trim(s, "[]")
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if n, err := strconv.Atoi(p); err == nil {
			result = append(result, n)
		}
	}
	return result
}

func formatIntList(nums []int) string {
	var parts []string
	for _, n := range nums {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ", ")
}
