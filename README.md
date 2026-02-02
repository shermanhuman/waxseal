# WaxSeal

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

## Quick Start

### 1. Initialize in your GitOps repo

```bash
cd my-infra-repo
waxseal init --project-id=my-gcp-project
```

This creates:

- `.waxseal/config.yaml` - Configuration file
- `.waxseal/metadata/` - Directory for secret metadata
- `keys/pub-cert.pem` - Placeholder for controller certificate

### 2. Fetch your Sealed Secrets controller certificate

```bash
kubeseal --controller-name=sealed-secrets --controller-namespace=kube-system \
  --fetch-cert > keys/pub-cert.pem
```

### 3. Discover existing SealedSecrets

```bash
waxseal discover
```

This finds SealedSecret manifests and creates metadata stubs in `.waxseal/metadata/`.

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
| `init`            | Initialize waxseal in a GitOps repository            |
| `discover`        | Find SealedSecrets and create metadata stubs         |
| `list`            | List registered secrets with status and expiry       |
| `validate`        | Validate repo and metadata consistency (CI-friendly) |
| `reseal`          | Reseal secrets from GSM to SealedSecret manifests    |
| `rotate`          | Rotate secret values and reseal                      |
| `reminders sync`  | Sync expiry reminders to Google Calendar             |
| `reminders clear` | Remove calendar reminders for a secret               |

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

# Test
go test ./...

# Run from source
go run ./cmd/waxseal --help
```

## License

[MIT](LICENSE)
