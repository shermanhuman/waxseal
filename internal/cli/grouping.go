package cli

// grouping.go sets command GroupIDs and hides advanced commands.
// This is kept in a single file for easy maintenance of the help layout.

func init() {
	// ── Primary help: visible commands with group labels ────────────

	// Key Management
	editCmd.GroupID = groupKeyMgmt
	rotateCmd.GroupID = groupKeyMgmt

	// Operations
	resealCmd.GroupID = groupOps
	checkCmd.GroupID = groupOps

	// Metadata
	metaCmd.GroupID = groupMeta

	// Installation
	setupCmd.GroupID = groupInstallation

	// ── Advanced: hidden from primary help ──────────────────────────

	addCmd.Hidden = true
	updateCmd.Hidden = true
	retireCmd.Hidden = true
	discoverCmd.Hidden = true
	gsmCmd.Hidden = true
	remindersCmd.Hidden = true

	// Cobra's built-in completion command
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
}
