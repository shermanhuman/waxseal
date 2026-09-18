package gcp

import "fmt"

// BootstrapParams describes the GCP resources waxseal needs.
type BootstrapParams struct {
	ProjectID        string
	CreateProject    bool
	BillingAccountID string // required when CreateProject
	FolderID         string // one of FolderID / OrganizationID when CreateProject
	OrganizationID   string
	ServiceAccountID string // default "waxseal"
	EnableReminders  bool   // also enable the Calendar API
	GitHubRepo       string // "owner/repo": set up Workload Identity for Actions
	Prefix           string // prefix for the Workload Identity pool, default ServiceAccountID
}

// ServiceAccountEmail returns the email of the service account the plan creates.
func (p BootstrapParams) ServiceAccountEmail() string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", p.serviceAccountID(), p.ProjectID)
}

func (p BootstrapParams) serviceAccountID() string {
	if p.ServiceAccountID == "" {
		return "waxseal"
	}
	return p.ServiceAccountID
}

func (p BootstrapParams) prefix() string {
	if p.Prefix == "" {
		return p.serviceAccountID()
	}
	return p.Prefix
}

// BootstrapPlan returns the gcloud steps that provision a project for
// waxseal. It is pure: rendering it is a dry run, Client.Apply executes it.
func BootstrapPlan(p BootstrapParams) []Step {
	var steps []Step
	project := "--project=" + p.ProjectID

	if p.CreateProject {
		create := []string{"projects", "create", p.ProjectID}
		switch {
		case p.FolderID != "":
			create = append(create, "--folder="+p.FolderID)
		case p.OrganizationID != "":
			create = append(create, "--organization="+p.OrganizationID)
		}
		steps = append(steps,
			Step{"Create project", create},
			Step{"Link billing account", []string{"billing", "projects", "link", p.ProjectID, "--billing-account=" + p.BillingAccountID}},
		)
	}

	apis := []string{"secretmanager.googleapis.com"}
	if p.EnableReminders {
		apis = append(apis, "calendar-json.googleapis.com", "tasks.googleapis.com")
	}
	steps = append(steps, Step{"Enable APIs", append([]string{"services", "enable", project}, apis...)})

	sa := p.serviceAccountID()
	steps = append(steps,
		Step{"Create service account", []string{"iam", "service-accounts", "create", sa, project,
			"--display-name=WaxSeal Service Account",
			"--description=Service account for WaxSeal SealedSecrets management"}},
		Step{"Grant Secret Manager Admin", []string{"projects", "add-iam-policy-binding", p.ProjectID,
			"--member=serviceAccount:" + p.ServiceAccountEmail(),
			"--role=roles/secretmanager.admin"}},
	)

	if p.GitHubRepo != "" {
		pool := p.prefix() + "-github-pool"
		provider := p.prefix() + "-github-provider"
		principal := fmt.Sprintf("principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.repository/%s",
			p.ProjectID, pool, p.GitHubRepo)
		steps = append(steps,
			Step{"Create Workload Identity Pool", []string{"iam", "workload-identity-pools", "create", pool, project,
				"--location=global", "--display-name=GitHub Actions Pool"}},
			Step{"Create OIDC Provider", []string{"iam", "workload-identity-pools", "providers", "create-oidc", provider, project,
				"--location=global", "--workload-identity-pool=" + pool, "--display-name=GitHub Actions",
				"--issuer-uri=https://token.actions.githubusercontent.com",
				"--attribute-mapping=google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository"}},
			Step{"Bind service account to Workload Identity", []string{"iam", "service-accounts", "add-iam-policy-binding", p.ServiceAccountEmail(), project,
				"--member=" + principal, "--role=roles/iam.workloadIdentityUser"}},
		)
	}
	return steps
}
