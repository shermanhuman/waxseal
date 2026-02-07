package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CheckGcloudInstalled returns an error if the gcloud CLI is not on PATH.
func CheckGcloudInstalled() error {
	_, err := exec.LookPath("gcloud")
	if err != nil {
		return fmt.Errorf(`gcloud CLI not found in PATH

WaxSeal uses gcloud to manage GCP infrastructure. 
Please install the Google Cloud SDK:
  https://cloud.google.com/sdk/docs/install`)
	}
	return nil
}

// ADCExists returns true if Application Default Credentials exist on disk.
func ADCExists() bool {
	home, _ := os.UserHomeDir()
	adcPath := filepath.Join(home, "AppData", "Roaming", "gcloud", "application_default_credentials.json")
	if os.Getenv("OS") != "Windows_NT" {
		adcPath = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	}
	_, err := os.Stat(adcPath)
	return err == nil
}

// ActiveAccount returns the current gcloud account, or "" if none.
func ActiveAccount() string {
	cmd := exec.Command("gcloud", "config", "get-value", "account")
	output, _ := cmd.Output()
	account := strings.TrimSpace(string(output))
	if account == "(unset)" {
		return ""
	}
	return account
}

// RunGcloud executes a gcloud command with a 5-minute timeout.
func RunGcloud(args ...string) error {
	return RunGcloudWithTimeout(5*time.Minute, args...)
}

// RunGcloudWithTimeout executes a gcloud command with a custom timeout.
func RunGcloudWithTimeout(timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("command timed out after %v - browser may not have opened correctly", timeout)
	}
	return err
}

// BillingAccount represents a GCP billing account.
type BillingAccount struct {
	Name        string `json:"name"`        // e.g. billingAccounts/01XXXX-XXXXXX-XXXXXX
	DisplayName string `json:"displayName"` // e.g. My Billing Account
	Open        bool   `json:"open"`
}

// GetBillingAccounts returns a list of available billing accounts for the current user.
func GetBillingAccounts() ([]BillingAccount, error) {
	cmd := exec.Command("gcloud", "billing", "accounts", "list", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list billing accounts: %w", err)
	}

	var accounts []BillingAccount
	if err := json.Unmarshal(output, &accounts); err != nil {
		return nil, fmt.Errorf("failed to parse billing accounts: %w", err)
	}

	return accounts, nil
}

// Project represents a GCP project.
type Project struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
}

// GetProjects returns a list of available GCP projects (max 50).
func GetProjects() ([]Project, error) {
	cmd := exec.Command("gcloud", "projects", "list", "--format=json", "--limit=50")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	var projects []Project
	if err := json.Unmarshal(output, &projects); err != nil {
		return nil, fmt.Errorf("failed to parse projects: %w", err)
	}

	return projects, nil
}

// Organization represents a GCP organization.
type Organization struct {
	Name        string `json:"name"`        // organizations/123456789
	DisplayName string `json:"displayName"` // example.com
}

// GetOrganizations returns a list of available GCP organizations.
// Returns nil, nil if the user lacks organization permissions.
func GetOrganizations() ([]Organization, error) {
	cmd := exec.Command("gcloud", "organizations", "list", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		// If command fails (e.g. no permissions), just return empty
		return nil, nil
	}

	var orgs []Organization
	if err := json.Unmarshal(output, &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}
