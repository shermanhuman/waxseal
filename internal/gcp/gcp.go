package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/proc"
)

// Client runs gcloud. The zero value is usable; tests inject a runner.
type Client struct {
	run        proc.Runner
	retryDelay time.Duration // tests shorten the propagation wait
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
	case strings.Contains(msg, "does not exist"):
		return fmt.Errorf("%w: %w", errNotPropagated, err)
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
// after every step with nil for success or skipped-as-done. A step that
// fails because a resource created by an earlier step "does not exist" yet
// is retried a few times: IAM sees a new service account only after a
// short propagation delay.
func (c Client) Apply(ctx context.Context, steps []Step, onStep func(Step, error)) error {
	for _, step := range steps {
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			_, err = c.runner()(ctx, nil, "gcloud", step.Args...)
			err = classify(err)
			if !errors.Is(err, errNotPropagated) {
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-time.After(c.propagationDelay()):
				continue
			}
			break
		}
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

// errNotPropagated marks a failure that IAM propagation will resolve.
var errNotPropagated = errors.New("resource not yet visible")

func (c Client) propagationDelay() time.Duration {
	if c.retryDelay > 0 {
		return c.retryDelay
	}
	return 3 * time.Second
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

// BillingAccount represents a GCP billing account.
type BillingAccount struct {
	Name        string `json:"name"`        // e.g. billingAccounts/01XXXX-XXXXXX-XXXXXX
	DisplayName string `json:"displayName"` // e.g. My Billing Account
	Open        bool   `json:"open"`
}

// Project represents a GCP project.
type Project struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
}

// Organization represents a GCP organization.
type Organization struct {
	Name        string `json:"name"`        // organizations/123456789
	DisplayName string `json:"displayName"` // example.com
}
