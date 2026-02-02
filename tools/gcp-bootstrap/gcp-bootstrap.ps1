<#
.SYNOPSIS
  Bootstraps a dedicated Google Cloud project for waxseal.

.DESCRIPTION
  Opinionated defaults:
  - Avoid service account keys.
  - Use Workload Identity Federation (GitHub OIDC) for CI automation.
  - Create dedicated service accounts + custom roles (least privilege).
  - Enable only required APIs.

  This script is designed to be re-run safely (idempotent-ish). It uses gcloud.

.REQUIREMENTS
  - gcloud CLI installed and authenticated.
  - Permissions to create/configure projects, IAM, and (optionally) billing.

.EXAMPLE
  ./gcp-bootstrap.ps1 -ProjectId waxseal-prod-123456 -CreateProject -BillingAccountId 000000-000000-000000 -FolderId 123456789012 -GitHubRepo shermanhuman/waxseal
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [string]$ProjectId,

  [Parameter(Mandatory = $false)]
  [switch]$CreateProject,

  [Parameter(Mandatory = $false)]
  [string]$FolderId,

  [Parameter(Mandatory = $false)]
  [string]$OrgId,

  [Parameter(Mandatory = $false)]
  [string]$BillingAccountId,

  [Parameter(Mandatory = $false)]
  [string]$GitHubRepo,

  [Parameter(Mandatory = $false)]
  [string]$DefaultBranchRef = "refs/heads/main",

  [Parameter(Mandatory = $false)]
  [switch]$EnableRemindersApi,

  [Parameter(Mandatory = $false)]
  [string]$SecretsPrefix = "waxseal-"
)

$ErrorActionPreference = "Stop"

function Exec {
  param([string]$Command)
  Write-Host $Command
  if ($PSCmdlet.ShouldProcess($Command)) {
    & powershell -NoProfile -Command $Command
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command" }
  }
}

function GCloud {
  param([string]$Args)
  Exec "gcloud $Args"
}

function TryGCloudJson {
  param([string]$Args)
  $cmd = "gcloud $Args --format=json"
  Write-Host $cmd
  if (-not $PSCmdlet.ShouldProcess($cmd)) { return $null }
  $out = & gcloud @($Args.Split(' ') + @('--format=json')) 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return ($out | Out-String | ConvertFrom-Json)
}

function EnsureProject {
  $existing = TryGCloudJson "projects describe $ProjectId"
  if ($null -ne $existing) { return }

  if (-not $CreateProject) {
    throw "Project '$ProjectId' does not exist. Re-run with -CreateProject (and -BillingAccountId, -FolderId/-OrgId)."
  }

  if ([string]::IsNullOrWhiteSpace($BillingAccountId)) {
    throw "-BillingAccountId is required when -CreateProject is set."
  }

  $parentArgs = ""
  if (-not [string]::IsNullOrWhiteSpace($FolderId)) {
    $parentArgs = "--folder $FolderId"
  } elseif (-not [string]::IsNullOrWhiteSpace($OrgId)) {
    $parentArgs = "--organization $OrgId"
  }

  GCloud "projects create $ProjectId $parentArgs"
  GCloud "beta billing projects link $ProjectId --billing-account $BillingAccountId"
}

function GetProjectNumber {
  $p = TryGCloudJson "projects describe $ProjectId"
  if ($null -eq $p) { throw "Unable to describe project '$ProjectId'." }
  return [string]$p.projectNumber
}

function EnableApis {
  $apis = @(
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "secretmanager.googleapis.com"
  )

  if ($EnableRemindersApi) {
    $apis += "calendar.googleapis.com"
  }

  $apiList = ($apis -join " ")
  GCloud "services enable $apiList --project $ProjectId"
}

function EnsureServiceAccount {
  param(
    [Parameter(Mandatory = $true)][string]$AccountId,
    [Parameter(Mandatory = $true)][string]$DisplayName
  )

  $email = "$AccountId@$ProjectId.iam.gserviceaccount.com"
  $existing = TryGCloudJson "iam service-accounts describe $email --project $ProjectId"
  if ($null -eq $existing) {
    GCloud "iam service-accounts create $AccountId --display-name=\"$DisplayName\" --project $ProjectId"
  }

  return $email
}

function EnsureCustomRole {
  param(
    [Parameter(Mandatory = $true)][string]$RoleId,
    [Parameter(Mandatory = $true)][string]$Title,
    [Parameter(Mandatory = $true)][string[]]$Permissions
  )

  $roleName = "projects/$ProjectId/roles/$RoleId"
  $existing = TryGCloudJson "iam roles describe $RoleId --project $ProjectId"

  $permList = ($Permissions -join ",")

  if ($null -eq $existing) {
    GCloud "iam roles create $RoleId --project $ProjectId --title=\"$Title\" --stage=GA --permissions=$permList"
  } else {
    # Keep it simple: update to the script-defined permissions.
    GCloud "iam roles update $RoleId --project $ProjectId --title=\"$Title\" --stage=GA --permissions=$permList"
  }

  return $roleName
}

function EnsureIamBinding {
  param(
    [Parameter(Mandatory = $true)][string]$Member,
    [Parameter(Mandatory = $true)][string]$Role,
    [Parameter(Mandatory = $false)][string]$ConditionTitle,
    [Parameter(Mandatory = $false)][string]$ConditionExpression
  )

  $condArgs = ""
  if (-not [string]::IsNullOrWhiteSpace($ConditionExpression)) {
    $condArgs = "--condition=\"title=$ConditionTitle,expression=$ConditionExpression\""
  }

  GCloud "projects add-iam-policy-binding $ProjectId --member=\"$Member\" --role=\"$Role\" $condArgs"
}

function EnsureWifForGitHub {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectNumber,
    [Parameter(Mandatory = $true)][string]$ServiceAccountEmail
  )

  if ([string]::IsNullOrWhiteSpace($GitHubRepo)) {
    Write-Host "Skipping GitHub OIDC setup (no -GitHubRepo)."
    return
  }

  $poolId = "waxseal-github"
  $providerId = "github"

  # Create pool if missing
  $pool = TryGCloudJson "iam workload-identity-pools describe $poolId --location=global --project=$ProjectId"
  if ($null -eq $pool) {
    GCloud "iam workload-identity-pools create $poolId --location=global --project=$ProjectId --display-name=\"waxseal GitHub Actions\""
  }

  # Create provider if missing
  $provider = TryGCloudJson "iam workload-identity-pools providers describe $providerId --location=global --workload-identity-pool=$poolId --project=$ProjectId"
  if ($null -eq $provider) {
    $issuer = "https://token.actions.githubusercontent.com"
    $mapping = "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref"
    $condition = "assertion.repository == '$GitHubRepo' && assertion.ref == '$DefaultBranchRef'"

    GCloud "iam workload-identity-pools providers create-oidc $providerId --location=global --workload-identity-pool=$poolId --project=$ProjectId --display-name=\"GitHub\" --issuer-uri=$issuer --attribute-mapping=\"$mapping\" --attribute-condition=\"$condition\""
  }

  # Allow identities from this repo to impersonate the service account.
  $principalSet = "principalSet://iam.googleapis.com/projects/$ProjectNumber/locations/global/workloadIdentityPools/$poolId/attribute.repository/$GitHubRepo"
  GCloud "iam service-accounts add-iam-policy-binding $ServiceAccountEmail --project $ProjectId --role=roles/iam.workloadIdentityUser --member=\"$principalSet\""

  Write-Host "\nGitHub OIDC configured. In GitHub Actions, use:" 
  Write-Host "- workload_identity_provider: projects/$ProjectNumber/locations/global/workloadIdentityPools/$poolId/providers/$providerId"
  Write-Host "- service_account: $ServiceAccountEmail\n"
}

# --- main ---
EnsureProject
GCloud "config set project $ProjectId"
EnableApis

$projectNumber = GetProjectNumber

# Custom roles (least privilege; avoid basic roles)
$resealRole = EnsureCustomRole -RoleId "waxsealReseal" -Title "waxseal reseal (read pinned versions)" -Permissions @(
  "secretmanager.secrets.get",
  "secretmanager.versions.access",
  "secretmanager.versions.get"
)

$rotateRole = EnsureCustomRole -RoleId "waxsealRotate" -Title "waxseal rotate/bootstrap (create secrets, add versions)" -Permissions @(
  "secretmanager.secrets.create",
  "secretmanager.secrets.get",
  "secretmanager.secrets.update",
  "secretmanager.versions.add",
  "secretmanager.versions.access",
  "secretmanager.versions.get"
)

# Service accounts (separate trust boundaries)
$ciSa = EnsureServiceAccount -AccountId "waxseal-ci" -DisplayName "waxseal CI (reseal/validate)"
$opsSa = EnsureServiceAccount -AccountId "waxseal-ops" -DisplayName "waxseal operator (bootstrap/rotate)"

# Restrict Secret Manager access to waxseal-owned secrets by naming convention.
# Note: this relies on using a dedicated secrets project + a strict prefix.
$prefixExpr = "resource.name.startsWith('projects/$projectNumber/secrets/$SecretsPrefix')"

EnsureIamBinding -Member "serviceAccount:$ciSa" -Role $resealRole -ConditionTitle "waxsealSecretsOnly" -ConditionExpression $prefixExpr
EnsureIamBinding -Member "serviceAccount:$opsSa" -Role $rotateRole -ConditionTitle "waxsealSecretsOnly" -ConditionExpression $prefixExpr

# Workload Identity Federation for GitHub Actions (no long-lived secrets)
EnsureWifForGitHub -ProjectNumber $projectNumber -ServiceAccountEmail $ciSa

Write-Host "Bootstrap complete."
Write-Host "- Project: $ProjectId ($projectNumber)"
Write-Host "- waxseal CI SA:  $ciSa"
Write-Host "- waxseal Ops SA: $opsSa"
Write-Host "- Secret prefix:  $SecretsPrefix"
