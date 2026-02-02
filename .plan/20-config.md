# Config Plan

## Files

In a GitOps repo that waxseal operates on:

- `.waxseal/config.yaml` (repo-local config)
- `.waxseal/metadata/*.yaml` (per-secret metadata and policies)
- `.waxseal/state.yaml` (non-secret state; committed)

Repo-local config is the source of truth.

We should not add user-level config in the initial versions unless we have a concrete need.
If we ever add it, it must be limited to non-policy defaults (e.g., default kube context, logging) and must never override repo policy.

## Config search order

1. `--config <path>` if provided
2. `<repo>/.waxseal/config.yaml`

## Minimal `.waxseal/config.yaml` fields

- `version` (schema version)
- `store`:
  - `kind`: `gsm`
  - `projectId`
  - `defaultReplication`: `automatic` | `user-managed` (optional)
  - `labels` (optional; applied to created GSM secrets)

Store plugin model (separation of concerns):

- `store.kind` is a plugin selection.
- v1 supports `gsm` only.
- The rest of waxseal code depends on a small “Secret Store” interface (access version, add version, optionally create secret) so other backends can be added later without rewriting core logic.

Note: “plugin” here means a compile-time implementation selected by config (no dynamic loading).

GSM version policy:

- waxseal always uses pinned numeric secret versions recorded in metadata.
- GSM aliases (including `latest`) are not supported.

- `controller`:
  - `namespace` (default `kube-system`)
  - `serviceName` (default `sealed-secrets`)
  - `keySecretLabel` (default `sealedsecrets.bitnami.com/sealed-secrets-key`)
- `cert`:
  - `repoCertPath` (default `keys/pub-cert.pem` relative to repo)
  - `verifyAgainstCluster` (default true)
- `discovery`:
  - `includeGlobs` (default `apps/**/*.yaml`)
  - `excludeGlobs` (default none)


- `bootstrap`:
  - `cluster`:
    - `enabled` (bool)
    - `kubeContext` (optional)
    - `allowReadingSecrets` (bool; explicit safety gate, default false)

- `reminders` (optional)
  - `enabled` (bool, default false)
  - `provider`: `google-calendar` (default)
  - `calendarId` (default `primary`)
  - `leadTimeDays` (default `[30, 7, 1]`)
  - `eventTitleTemplate` (optional)
    - default: `[waxseal] Rotate {{shortName}}/{{keyName}} (expires {{expiresAt}})`

  - `auth` (required if `enabled: true`)
    - `kind`: `adc` (required in v1)
    - Semantics: waxseal uses Application Default Credentials; no reminder credentials are stored in Git or GSM.

## Notes

- Do not store secret values in config.

Non-goal for v1:

- Containerized fallback execution. waxseal is a single binary; CI should install dependencies explicitly.

GSM guidance (implementation relevant):

- Auth: use Application Default Credentials (ADC).
- Prefer version pinning (per GSM best practices) to avoid accidental value changes during reseal.

Provisioning guidance (operator workflow):

- Prefer deterministic, no-click-ops GCP-side setup via `waxseal gcp bootstrap`.
- For CI: prefer Workload Identity Federation (GitHub OIDC) instead of long-lived secrets.

Calendar guidance (implementation relevant):

- Auth: use ADC.
- Operators must ensure ADC has Calendar scope and can write to the chosen calendar.

## On “GCS as a secret store”

- Prefer Google Secret Manager (GSM) as the backing store for plaintext.
- Plaintext secrets in Google Cloud Storage (GCS) are strongly discouraged; if ever supported it must be:
  - explicitly opt-in
  - encrypted with KMS (CMEK)
  - treated as a backup/export mechanism, not a source of truth
