# WaxSeal

![waxseal-logo](https://github.com/user-attachments/assets/a914aa45-7945-429e-ac22-723654557e4e)

> GitOps-friendly SealedSecrets management with Google Secret Manager as the source of truth.

WaxSeal keeps plaintext out of Git by synchronizing Kubernetes SealedSecrets with Google Secret Manager (GSM). All secret values live in GSM; Git stores only encrypted ciphertext and metadata.

## Installation

```bash
go install github.com/shermanhuman/waxseal/cmd/waxseal@latest
```

Or build from source:

```bash
git clone https://github.com/shermanhuman/waxseal.git
cd waxseal
go build -o waxseal ./cmd/waxseal
```

## Prerequisites

Before using waxseal, ensure you have:

- **gcloud CLI** - Authenticated with `gcloud auth application-default login`
- **kubeseal CLI** - Available on PATH (used for encryption)
- **kubectl** - Configured to access your cluster
- **A Kubernetes cluster** with [SealedSecrets controller](https://github.com/bitnami-labs/sealed-secrets) installed
- **A GitOps repository** with existing SealedSecret manifests (or starting fresh)

## Quick Start

### 1. Initialize in your GitOps repo

```bash
cd my-infra-repo
waxseal setup
```

The interactive wizard will:

- Create/configure your GCP project for secret storage
- Enable required APIs (Secret Manager)
- Set up billing if needed
- Fetch the sealing certificate from your cluster
- Create configuration files

This creates:

- `.waxseal/config.yaml` - Configuration file
- `.waxseal/metadata/` - Directory for secret metadata
- `keys/pub-cert.pem` - Controller certificate (fetched from cluster)

### 2. Discover existing SealedSecrets

```bash
waxseal discover
```

This finds SealedSecret manifests and creates metadata stubs in `.waxseal/metadata/`.

### 3. Bootstrap secrets to GSM

```bash
# Push existing cluster secret values to GSM
waxseal bootstrap my-app-secrets
```

### 4. Reseal secrets

```bash
# Reseal a single secret
waxseal reseal my-app-secrets

# Reseal all active secrets
waxseal reseal --all

# Dry run to see what would be done
waxseal reseal --all --dry-run
```

## Commands

| Command           | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `setup`           | Interactive setup wizard for a GitOps repository     |
| `discover`        | Find SealedSecrets and create metadata stubs         |
| `list`            | List registered secrets with status and expiry       |
| `validate`        | Validate repo and metadata consistency (CI-friendly) |
| `reseal`          | Reseal secrets from GSM to SealedSecret manifests    |
| `rotate`          | Rotate secret values and reseal                      |
| `retire`          | Mark a secret as retired and optionally delete       |
| `reencrypt`       | Re-encrypt all secrets with new cluster certificate  |
| `bootstrap`       | Push existing cluster secrets to GSM                 |
| `cert-check`      | Check sealing certificate expiry                     |
| `gcp bootstrap`   | Set up GCP infrastructure for WaxSeal                |
| `reminders sync`  | Sync expiry reminders to Google Calendar             |
| `reminders clear` | Remove calendar reminders for a secret               |
| `reminders list`  | List secrets with upcoming expiry                    |
| `reminders setup` | Configure reminder settings                          |

### Global Flags

| Flag        | Description                                           |
| ----------- | ----------------------------------------------------- |
| `--repo`    | Path to GitOps repository (default: `.`)              |
| `--config`  | Path to config file (default: `.waxseal/config.yaml`) |
| `--dry-run` | Preview changes without writing                       |
| `--yes`     | Skip confirmation prompts                             |

## Configuration

`.waxseal/config.yaml`:

```yaml
version: "1"

store:
  kind: gsm
  projectId: my-gcp-project

controller:
  namespace: kube-system
  serviceName: sealed-secrets

cert:
  repoCertPath: keys/pub-cert.pem
  verifyAgainstCluster: true

discovery:
  includeGlobs:
    - "apps/**/*.yaml"
  excludeGlobs:
    - "**/kustomization.yaml"

# Optional: Google Calendar reminders for expiry
reminders:
  enabled: true
  provider: google-calendar
  calendarId: primary
  leadTimeDays: [30, 7, 1]
  auth:
    kind: adc
```

## Metadata Schema

Each secret has a metadata file in `.waxseal/metadata/<shortName>.yaml`:

```yaml
shortName: my-app-secrets
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-app-secrets
  namespace: my-app
  scope: strict
  type: Opaque
status: active

keys:
  # GSM-backed key with auto-rotation
  - keyName: api_key
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-app-api-key
      version: "3"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32

  # External credential (OAuth, third-party API, etc.)
  - keyName: oauth_secret
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-project/secrets/my-app-oauth
      version: "1"
    rotation:
      mode: external
    expiry:
      expiresAt: "2026-06-15T00:00:00Z"

  # Computed key (DATABASE_URL pattern)
  - keyName: DATABASE_URL
    source:
      kind: computed
    computed:
      kind: template
      template: "postgresql://{{user}}:{{pass}}@{{host}}:5432/{{db}}"
      inputs:
        - var: user
          ref:
            keyName: db_username
        - var: pass
          ref:
            keyName: db_password
      params:
        host: "db.example.com"
        db: "myapp"
```

## Rotation Modes

| Mode        | Description                         | Use Case                          |
| ----------- | ----------------------------------- | --------------------------------- |
| `generated` | Auto-generate new value on rotate   | API keys, passwords, tokens       |
| `external`  | Manual update, waxseal reseals      | OAuth secrets, third-party tokens |
| `manual`    | Operator updates in external system | Legacy systems                    |

### Rotating Secrets

```bash
# Rotate a specific key (auto-generates if mode=generated)
waxseal rotate my-app-secrets api_key

# Rotate all generated keys in a secret
waxseal rotate my-app-secrets --generated
```

## Computed Keys

Computed keys are derived from other keys using templates. Common use case: `DATABASE_URL` from individual credentials.

Template syntax: `{{variable_name}}`

```yaml
- keyName: DATABASE_URL
  source:
    kind: computed
  computed:
    kind: template
    template: "postgresql://{{user}}:{{pass}}@{{host}}:{{port}}/{{db}}"
    inputs:
      - var: user
        ref:
          keyName: db_username # Same secret
      - var: pass
        ref:
          keyName: db_password
    params:
      host: "db.example.com"
      port: "5432"
      db: "myapp"
```

## Expiry and Reminders

Track secret expiration and get calendar reminders:

```yaml
- keyName: tls_cert
  expiry:
    expiresAt: "2026-03-01T00:00:00Z"
    source: "cert-notAfter"
```

Sync to Google Calendar:

```bash
waxseal reminders sync
```

This creates events at 30, 7, and 1 days before expiry.

## Retiring Secrets

When a secret is no longer needed, retire it instead of deleting:

```bash
# Mark as retired
waxseal retire my-app-secrets --reason "Migrated to new service"

# Retire and delete the manifest file
waxseal retire my-app-secrets --delete-manifest

# Retire and link to replacement
waxseal retire old-secret --replaced-by new-secret
```

Retired secrets are skipped during `reseal --all` operations.

## Re-encrypting After Cert Rotation

When the SealedSecrets controller certificate rotates:

```bash
# Fetch new cert from cluster and re-encrypt all secrets
waxseal reencrypt

# Use a specific new certificate file
waxseal reencrypt --new-cert /path/to/new-cert.pem

# Preview what would be done
waxseal reencrypt --dry-run
```

## Bootstrapping Existing Secrets

Import existing Kubernetes secrets to GSM:

```bash
# Push a discovered secret's values to GSM
waxseal bootstrap my-app-secrets

# Preview without making changes
waxseal bootstrap my-app-secrets --dry-run
```

This reads the secret from the cluster and pushes values to GSM.

## Certificate Expiry Checking

Monitor your sealing certificate:

```bash
# Check certificate expiry
waxseal cert-check

# Warn if expiring within 90 days
waxseal cert-check --warn-days 90

# Fail in CI if expiring soon
waxseal cert-check --fail-on-warning
```

Exit codes:

- `0` - Certificate valid
- `1` - Certificate expired
- `2` - Certificate expiring soon (with `--fail-on-warning`)

## GCP Infrastructure Setup

Set up GCP project for WaxSeal:

```bash
# Bootstrap existing project
waxseal gcp bootstrap --project-id my-project

# Create new project with billing
waxseal gcp bootstrap --project-id my-project --create-project \
  --billing-account-id 01XXXX-XXXXXX

# Set up Workload Identity for GitHub Actions
waxseal gcp bootstrap --project-id my-project \
  --github-repo owner/repo

# Preview what would be done
waxseal gcp bootstrap --project-id my-project --dry-run
```

## Operator Hints

Provide guidance for manual rotation:

```yaml
- keyName: stripe_key
  operatorHints:
    provider: stripe
    rotationUrl: https://dashboard.stripe.com/apikeys
    docUrl: https://stripe.com/docs/keys
    contact: platform-team@company.com
    notes: "Regenerate in Stripe Dashboard, then update GSM"
```

During `waxseal rotate`, hints are displayed to guide operators.

## CI/CD Integration

### Validation

```yaml
# GitHub Actions example
- name: Validate waxseal
  run: waxseal validate --soon-days=30
```

Exit codes:

- `0` - Success
- `2` - Validation failed

### Automated Reseal

```yaml
- name: Reseal all secrets
  run: waxseal reseal --all
  env:
    GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_SA_KEY }}
```

## Security

**Critical invariants enforced by waxseal:**

1. **No plaintext on disk** - Secrets are never written unencrypted
2. **No secrets in logs** - The `Redacted` type prevents accidental logging
3. **Numeric GSM versions only** - Aliases like `latest` are rejected to ensure reproducibility
4. **Atomic writes** - Files are written to temp then renamed, preventing corruption
5. **Validation before write** - Output is validated before replacing files
6. **Controller-compatible encryption** - Uses `kubeseal` binary for encryption to guarantee compatibility

## Authentication

WaxSeal uses Application Default Credentials (ADC) for GCP authentication:

```bash
# Development
gcloud auth application-default login

# Production (Service Account)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json

# GKE Workload Identity
# Automatic when running in GKE with configured Workload Identity
```

Required IAM roles:

- `roles/secretmanager.secretAccessor` - Read secret values
- `roles/secretmanager.secretVersionAdder` - Add new versions (for rotation)

## Development

```bash
# Build
go build ./...

# Unit tests
go test ./...

# E2E tests (requires Docker Desktop only)
docker compose -f docker-compose.e2e.yaml up --build

# Lint
golangci-lint run ./...

# Release builds
GOOS=linux go build -o waxseal-linux ./cmd/waxseal
```

## License

[MIT](LICENSE)
