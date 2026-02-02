# GCP bootstrap (waxseal)

Run the script to create/configure a dedicated GCP project for waxseal.

- No service account keys.
- GitHub Actions uses OIDC → Workload Identity Federation.
- Least-privilege custom roles.

## Run (PowerShell)

```powershell
cd tools/gcp-bootstrap
./gcp-bootstrap.ps1 -ProjectId <project-id> -CreateProject -BillingAccountId <billing-id> -FolderId <folder-id> -GitHubRepo <owner/repo>
```

If the project already exists, omit `-CreateProject` and billing/folder/org flags.

Optional:

- `-EnableRemindersApi` to enable `calendar.googleapis.com`.
- `-DefaultBranchRef refs/heads/main` to restrict GitHub OIDC to a branch.
- `-SecretsPrefix waxseal-` to scope Secret Manager access by naming convention.
