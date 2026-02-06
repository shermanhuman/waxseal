package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
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
  provider: tasks  # tasks (default), calendar, both, none
  # tasklistId: "@default"  # Optional, defaults to user's primary task list
  # calendarId: primary     # Only needed if provider is calendar or both
  leadTimeDays: [30, 7, 1]
  auth:
    kind: adc
`)
		return nil
	}

	if cfg.Reminders.Provider == "none" {
		fmt.Println("Reminders provider is set to 'none'. Nothing to sync.")
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

	// Create providers based on config
	var providers []reminders.Provider

	switch cfg.Reminders.Provider {
	case "tasks", "": // Tasks is default
		p, err := reminders.NewGoogleTasksProvider(ctx, cfg.Reminders.TasklistID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create tasks provider: %w", err)
		}
		fmt.Println("Using Google Tasks (tasks appear in Calendar)")
		providers = append(providers, p)

	case "calendar":
		p, err := reminders.NewGoogleCalendarProvider(ctx, cfg.Reminders.CalendarID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create calendar provider: %w", err)
		}
		fmt.Println("Using Google Calendar events")
		providers = append(providers, p)

	case "both":
		tp, err := reminders.NewGoogleTasksProvider(ctx, cfg.Reminders.TasklistID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create tasks provider: %w", err)
		}
		cp, err := reminders.NewGoogleCalendarProvider(ctx, cfg.Reminders.CalendarID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create calendar provider: %w", err)
		}
		fmt.Println("Using both Google Tasks and Calendar events")
		providers = append(providers, tp, cp)

	default:
		return fmt.Errorf("unknown provider: %s (use: tasks, calendar, both, none)", cfg.Reminders.Provider)
	}

	// Sync to all providers
	var totalCreated, totalUpdated, totalSkipped int
	var allErrors []error

	for _, provider := range providers {
		result, err := provider.SyncReminders(ctx, expiringSecrets)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("sync reminders: %w", err))
			continue
		}
		totalCreated += result.Created
		totalUpdated += result.Updated
		totalSkipped += result.Skipped
		allErrors = append(allErrors, result.Errors...)
	}

	fmt.Printf("✓ Created: %d, Updated: %d, Skipped: %d\n",
		totalCreated, totalUpdated, totalSkipped)

	if len(allErrors) > 0 {
		fmt.Fprintf(os.Stderr, "\nErrors:\n")
		for _, e := range allErrors {
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

	// Create providers based on config
	var providers []reminders.Provider

	switch cfg.Reminders.Provider {
	case "tasks", "": // Tasks is default
		p, err := reminders.NewGoogleTasksProvider(ctx, cfg.Reminders.TasklistID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create tasks provider: %w", err)
		}
		providers = append(providers, p)

	case "calendar":
		p, err := reminders.NewGoogleCalendarProvider(ctx, cfg.Reminders.CalendarID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create calendar provider: %w", err)
		}
		providers = append(providers, p)

	case "both":
		tp, err := reminders.NewGoogleTasksProvider(ctx, cfg.Reminders.TasklistID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create tasks provider: %w", err)
		}
		cp, err := reminders.NewGoogleCalendarProvider(ctx, cfg.Reminders.CalendarID, cfg.Reminders.LeadTimeDays)
		if err != nil {
			return fmt.Errorf("create calendar provider: %w", err)
		}
		providers = append(providers, tp, cp)

	case "none":
		fmt.Println("Reminders provider is set to 'none'. Nothing to clear.")
		return nil

	default:
		return fmt.Errorf("unknown provider: %s", cfg.Reminders.Provider)
	}

	for _, provider := range providers {
		if err := provider.DeleteReminders(ctx, shortName); err != nil {
			return fmt.Errorf("delete reminders: %w", err)
		}
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
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              WaxSeal Reminders Setup                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Check for existing config
	configFile := configPath
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(repoPath, configFile)
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("No config file found. Run 'waxseal setup' first.")
		return nil
	}

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
	var provider string
	err := huh.NewSelect[string]().
		Title("Which reminder provider(s) would you like to use?").
		Options(
			huh.NewOption("📋 Google Tasks only (recommended)", "tasks"),
			huh.NewOption("📅 Google Calendar only", "calendar"),
			huh.NewOption("🔔 Both Tasks and Calendar", "both"),
			huh.NewOption("❌ Disable reminders", "none"),
		).
		Value(&provider).
		Run()
	if err != nil {
		return err
	}

	if provider == "none" {
		fmt.Println("Reminders disabled. You can run 'waxseal reminders setup' again to enable.")
		return nil
	}

	// Lead time days
	leadTimeStr := "30, 7, 1"
	err = huh.NewInput().
		Title("Lead Time Days").
		Description("Comma-separated days before expiry to create reminders (e.g., '30, 7, 1')").
		Value(&leadTimeStr).
		Validate(func(s string) error {
			if len(parseIntList(s)) == 0 {
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
	if provider == "tasks" || provider == "both" {
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
			Affirmative("Yes, specify").
			Negative("No, use default").
			Run()
		if err != nil {
			return err
		}

		if customTasklist {
			err = huh.NewInput().
				Title("Task List ID").
				Description("Enter your task list ID").
				Value(&tasklistID).
				Run()
			if err != nil {
				return err
			}
		}
	}

	// Calendar configuration
	calendarID := "primary"
	if provider == "calendar" || provider == "both" {
		fmt.Println()
		fmt.Println("📅 Google Calendar Configuration")
		fmt.Println("   'primary' uses the calendar of the authenticated Google account.")
		fmt.Println()

		err = huh.NewInput().
			Title("Calendar ID").
			Description("Use 'primary' or a calendar email").
			Value(&calendarID).
			Run()
		if err != nil {
			return err
		}
	}

	// Build config snippet
	leadTimeDays := parseIntList(leadTimeStr)
	var configSnippet strings.Builder
	configSnippet.WriteString("\nreminders:\n")
	configSnippet.WriteString("  enabled: true\n")
	configSnippet.WriteString(fmt.Sprintf("  provider: %s\n", provider))
	if (provider == "tasks" || provider == "both") && tasklistID != "@default" {
		configSnippet.WriteString(fmt.Sprintf("  tasklistId: \"%s\"\n", tasklistID))
	}
	if provider == "calendar" || provider == "both" {
		configSnippet.WriteString(fmt.Sprintf("  calendarId: %s\n", calendarID))
	}
	configSnippet.WriteString(fmt.Sprintf("  leadTimeDays: [%s]\n", formatIntList(leadTimeDays)))
	configSnippet.WriteString("  auth:\n")
	configSnippet.WriteString("    kind: adc\n")

	fmt.Println()
	fmt.Println("Generated Configuration:")
	fmt.Println("┌─────────────────────────────────────────────────────")
	for _, line := range strings.Split(configSnippet.String(), "\n") {
		fmt.Printf("│ %s\n", line)
	}
	fmt.Println("└─────────────────────────────────────────────────────")

	if dryRun {
		fmt.Println("[DRY RUN] Would update config file")
		return nil
	}

	// Update Config
	var update bool
	err = huh.NewConfirm().
		Title("Update config file automatically?").
		Value(&update).
		Run()
	if err != nil {
		return nil
	}

	if !update {
		fmt.Println("Config not updated. Please add the snippet manually.")
		return nil
	}

	// Read existing config
	existingConfig, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Check if reminders already exists
	if strings.Contains(string(existingConfig), "reminders:") {
		fmt.Println("Config already contains reminders section. Please update manually.")
		return nil
	}

	// Append reminders config
	newConfig := string(existingConfig) + configSnippet.String()
	if err := os.WriteFile(configFile, []byte(newConfig), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Println("✓ Config updated successfully")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'waxseal reminders sync' to create reminders")
	fmt.Println("  2. Check your calendar/tasks to verify they were created")

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
