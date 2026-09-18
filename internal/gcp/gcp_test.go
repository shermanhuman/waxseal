package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/proc"
)

func TestBootstrapPlan(t *testing.T) {
	descs := func(steps []Step) string {
		var d []string
		for _, s := range steps {
			d = append(d, s.Desc)
		}
		return strings.Join(d, ", ")
	}

	minimal := BootstrapPlan(BootstrapParams{ProjectID: "p"})
	if got := descs(minimal); got != "Enable APIs, Create service account, Grant Secret Manager Admin" {
		t.Errorf("minimal plan: %s", got)
	}
	if !strings.Contains(strings.Join(minimal[2].Args, " "), "serviceAccount:waxseal@p.iam.gserviceaccount.com") {
		t.Errorf("default service account not used: %v", minimal[2].Args)
	}

	full := BootstrapPlan(BootstrapParams{ProjectID: "p", CreateProject: true, BillingAccountID: "B", FolderID: "F",
		OrganizationID: "O", EnableReminders: true, GitHubRepo: "me/repo"})
	if got := descs(full); got != "Create project, Link billing account, Enable APIs, Create service account, "+
		"Grant Secret Manager Admin, Create Workload Identity Pool, Create OIDC Provider, Bind service account to Workload Identity" {
		t.Errorf("full plan: %s", got)
	}
	if args := strings.Join(full[0].Args, " "); args != "projects create p --folder=F" {
		t.Errorf("folder must win over organization: %s", args)
	}
	if args := strings.Join(full[2].Args, " "); !strings.Contains(args, "calendar-json.googleapis.com") {
		t.Errorf("reminders should enable the calendar API: %s", args)
	}
	if args := strings.Join(full[7].Args, " "); !strings.Contains(args, "attribute.repository/me/repo") {
		t.Errorf("workload identity principal: %s", args)
	}
}

func TestApply_TreatsAlreadyExistsAsDone(t *testing.T) {
	var ran []string
	c := Client{run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		ran = append(ran, args[0])
		switch args[0] {
		case "exists":
			return nil, &proc.ExitError{Name: "gcloud", Code: 1, Stderr: "ERROR: Service account exists already Exists"}
		case "taken":
			return nil, &proc.ExitError{Name: "gcloud", Code: 1, Stderr: "ERROR: The project ID you specified is already in use by another project"}
		}
		return nil, nil
	}}

	var seen []error
	err := c.Apply(context.Background(), []Step{{"a", []string{"ok"}}, {"b", []string{"exists"}}, {"c", []string{"taken"}}, {"d", []string{"never"}}},
		func(_ Step, err error) { seen = append(seen, err) })
	if !errors.Is(err, ErrProjectIDTaken) {
		t.Errorf("got %v, want ErrProjectIDTaken", err)
	}
	if strings.Join(ran, ",") != "ok,exists,taken" {
		t.Errorf("ran %v; must stop at the failing step", ran)
	}
	if len(seen) != 3 || seen[0] != nil || seen[1] != nil || seen[2] == nil {
		t.Errorf("onStep errors = %v; 'already exists' must count as done", seen)
	}
}

func TestClient_Queries(t *testing.T) {
	c := Client{run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "billing accounts list --format=json":
			return []byte(`[{"name":"billingAccounts/01","displayName":"Main","open":true}]`), nil
		case "billing projects describe p --format=value(billingAccountName)":
			return []byte("billingAccounts/01\n"), nil
		case "config get-value account":
			return []byte("(unset)\n"), nil
		case "organizations list --format=json":
			return nil, &proc.ExitError{Name: "gcloud", Code: 1, Stderr: "PERMISSION_DENIED"}
		}
		t.Fatalf("unexpected: %v", args)
		return nil, nil
	}}
	ctx := context.Background()
	if accts, err := c.BillingAccounts(ctx); err != nil || len(accts) != 1 || accts[0].DisplayName != "Main" {
		t.Errorf("BillingAccounts = %v, %v", accts, err)
	}
	if got, err := c.BillingAccountOf(ctx, "p"); err != nil || got != "billingAccounts/01" {
		t.Errorf("BillingAccountOf = %q, %v", got, err)
	}
	if got := c.ActiveAccount(ctx); got != "" {
		t.Errorf("ActiveAccount = %q, want empty for (unset)", got)
	}
	if orgs, err := c.Organizations(ctx); err != nil || orgs != nil {
		t.Errorf("Organizations without permission = %v, %v; want none, no error", orgs, err)
	}
}

func TestClassify(t *testing.T) {
	if got := classify(nil); got != nil {
		t.Error("nil must stay nil")
	}
	plain := errors.New("x")
	if got := classify(plain); got != plain {
		t.Error("non-exit errors must pass through")
	}
	exists := classify(&proc.ExitError{Name: "gcloud", Stderr: "already exists"})
	if !errors.Is(exists, core.ErrAlreadyExists) {
		t.Errorf("got %v", exists)
	}
}

// IAM sees a new service account only after a moment; the binding step
// must be retried rather than failed.
func TestApply_RetriesUntilPropagated(t *testing.T) {
	calls := 0
	c := Client{retryDelay: time.Millisecond, run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		calls++
		if calls < 3 {
			return nil, &proc.ExitError{Name: "gcloud", Code: 1, Stderr: "ERROR: INVALID_ARGUMENT: Service account x does not exist."}
		}
		return nil, nil
	}}
	if err := c.Apply(context.Background(), []Step{{"Bind", []string{"projects", "add-iam-policy-binding"}}}, nil); err != nil {
		t.Fatalf("got %v after %d calls", err, calls)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}

	stuck := Client{retryDelay: time.Millisecond, run: func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, &proc.ExitError{Name: "gcloud", Code: 1, Stderr: "does not exist"}
	}}
	if err := stuck.Apply(context.Background(), []Step{{"Bind", []string{"x"}}}, nil); err == nil {
		t.Error("must give up eventually")
	}
}
