package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/proc"
)

// Client runs gcloud. The zero value is usable; tests inject a runner.
type Client struct {
	run proc.Runner
}

func (c Client) runner() proc.Runner {
	if c.run == nil {
		return proc.Run
	}
	return c.run
}

// ErrProjectIDTaken is wrapped when a project ID is already in use by
// someone else, so it cannot be created or reused.
var ErrProjectIDTaken = errors.New("project ID is already in use")

// classify turns gcloud's stderr into sentinel errors where a caller needs
// to branch. It is the only place that inspects gcloud's wording.
func classify(err error) error {
	var exitErr *proc.ExitError
	if !errors.As(err, &exitErr) {
		return err
	}
	msg := strings.ToLower(exitErr.Stderr)
	switch {
	case strings.Contains(msg, "already in use"):
		return fmt.Errorf("%w: %w", ErrProjectIDTaken, err)
	case strings.Contains(msg, "already exists"):
		return fmt.Errorf("%w: %w", core.ErrAlreadyExists, err)
	}
	return err
}

func (c Client) json(ctx context.Context, v any, args ...string) error {
	out, err := c.runner()(ctx, nil, "gcloud", append(args, "--format=json")...)
	if err != nil {
		return classify(err)
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("parse gcloud output: %w", err)
	}
	return nil
}

// ActiveAccount returns the current gcloud account, or "" if none.
func (c Client) ActiveAccount(ctx context.Context) string {
	out, _ := c.runner()(ctx, nil, "gcloud", "config", "get-value", "account")
	account := strings.TrimSpace(string(out))
	if account == "(unset)" {
		return ""
	}
	return account
}

// BillingAccounts lists the billing accounts the user can see.
func (c Client) BillingAccounts(ctx context.Context) ([]BillingAccount, error) {
	var accounts []BillingAccount
	err := c.json(ctx, &accounts, "billing", "accounts", "list")
	return accounts, err
}

// Projects lists up to 50 projects the user can see.
func (c Client) Projects(ctx context.Context) ([]Project, error) {
	var projects []Project
	err := c.json(ctx, &projects, "projects", "list", "--limit=50")
	return projects, err
}

// Organizations lists organizations; users without org permissions see none.
func (c Client) Organizations(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	if err := c.json(ctx, &orgs, "organizations", "list"); err != nil {
		return nil, nil
	}
	return orgs, nil
}

// BillingAccountOf returns the billing account linked to a project, or "".
func (c Client) BillingAccountOf(ctx context.Context, projectID string) (string, error) {
	out, err := c.runner()(ctx, nil, "gcloud", "billing", "projects", "describe", projectID, "--format=value(billingAccountName)")
	if err != nil {
		return "", classify(err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Step is one gcloud invocation in a plan.
type Step struct {
	Desc string
	Args []string
}

// Apply runs each step, treating "already exists" as done. onStep is called
// after every step with nil for success or skipped-as-done.
func (c Client) Apply(ctx context.Context, steps []Step, onStep func(Step, error)) error {
	for _, step := range steps {
		_, err := c.runner()(ctx, nil, "gcloud", step.Args...)
		err = classify(err)
		if errors.Is(err, core.ErrAlreadyExists) {
			err = nil
		}
		if onStep != nil {
			onStep(step, err)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", strings.ToLower(step.Desc), err)
		}
	}
	return nil
}

// Interactive runs gcloud attached to the terminal, for flows such as
// `auth login` that open a browser and wait for the user.
func (c Client) Interactive(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("gcloud %s timed out; the browser may not have opened", strings.Join(args, " "))
	}
	return err
}

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
//
// Deprecated: use Client.ActiveAccount; removed with the old CLI.
func ActiveAccount() string { return Client{}.ActiveAccount(context.Background()) }

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
//
// Deprecated: use Client.BillingAccounts; removed with the old CLI.
func GetBillingAccounts() ([]BillingAccount, error) {
	return Client{}.BillingAccounts(context.Background())
}

// Project represents a GCP project.
type Project struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
}

// GetProjects returns a list of available GCP projects (max 50).
//
// Deprecated: use Client.Projects; removed with the old CLI.
func GetProjects() ([]Project, error) { return Client{}.Projects(context.Background()) }

// Organization represents a GCP organization.
type Organization struct {
	Name        string `json:"name"`        // organizations/123456789
	DisplayName string `json:"displayName"` // example.com
}

// GetOrganizations returns a list of available GCP organizations.
// Returns nil, nil if the user lacks organization permissions.
//
// Deprecated: use Client.Organizations; removed with the old CLI.
func GetOrganizations() ([]Organization, error) { return Client{}.Organizations(context.Background()) }
