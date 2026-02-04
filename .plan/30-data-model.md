# Data Model Plan

## Per-secret metadata (`.waxseal/metadata/<shortName>.yaml`)

Identity:

- `shortName` (stable identifier used in CLI)
- `manifestPath` (path to SealedSecret YAML in repo)
- `sealedSecret`:
  - `name`
  - `namespace`
  - `scope` (`strict` | `namespace-wide` | `cluster-wide`)
  - `type` (optional; e.g., `kubernetes.io/dockerconfigjson`)

Lifecycle:

- `status`: `active` | `retired`
- `retiredAt` (optional, RFC3339)
- `retireReason` (optional)
- `replacedBy` (optional; `shortName`)

Keys:

- `keys[]`:
  - `keyName`
  - `source`:
    - `kind`: `gsm` | `computed`

  - `gsm` (required if `source.kind: gsm`)
    - `secretResource`: `projects/<project>/secrets/<secretId>`
    - `version`: string
      - default: numeric version (pinned)
      - must be a numeric version (pinned); GSM aliases like `latest` are not supported
    - `etag` (optional; for optimistic concurrency)

  - `rotation` (only if `source.kind: gsm`)
    - `mode`: `generated` | `external` | `manual` | `unknown`
      - `unknown` is the safe default when adopting existing ciphertext-only manifests.
    - `generator` (if `mode: generated`)
      - `kind`: `randomBase64` | `randomHex` | `randomBytes`
      - `bytes` or `chars`

  - `expiry` (optional; for credentials that have a real expiration)
    - `expiresAt` (RFC3339)
    - `source` (optional): `vendor` | `certificate` | `policy` | `unknown`
    - Semantics:
      - `expiresAt` applies to the currently pinned GSM version for this key.
      - When `rotate` updates the pinned GSM version, it must also update `expiresAt` when present.

  - `operatorHints` (optional, recommended for `rotation.mode: external|manual`)
    - Goal: keep rotation URLs, runbook notes, and other guidance out of Git.
    - Stored in GSM as non-secret-but-sensitive operational text.
    - `gsm`:
      - `secretResource`: `projects/<project>/secrets/<secretId>`
      - `version`: string (pinned)
    - `format`: `json` (required)
    - JSON schema inside the GSM payload (v1):
      - `schemaVersion`: `1`
      - `links[]`: `{ "label": string, "url": string }`
      - `notes`: string (optional)

  - `computed` (required if `source.kind: computed`)
    - `kind`: `template`
    - `gsm`:
      - `secretResource`: `projects/<project>/secrets/<secretId>`
      - `version`: string (pinned)
    - `rotation`:
      - `mode`: `generated` (the `{{secret}}` variable is auto-generated)
      - `generator`:
        - `kind`: `randomBase64` | `randomHex`
        - `bytes`: integer (default 32)

GSM payload schema (JSON stored in the GSM secret):

```json
{
  "schemaVersion": 1,
  "type": "templated",
  "template": "postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}",
  "values": {
    "username": "myapp_user",
    "host": "shared-postgres-rw",
    "port": "5432",
    "database": "breakdown_admin_prod"
  },
  "secret": "aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3JldA==",
  "generator": {
    "kind": "randomBase64",
    "bytes": 32
  },
  "computed": "postgresql://myapp_user:aGVsbG8t...@host:5432/db"
}
```

Standard variable: `{{secret}}` is always the rotatable credential.
Other variables (`{{username}}`, `{{host}}`, etc.) are stored in `values`.

Password length limits by database (32 bytes base64 = 44 chars is safe for all):

- PostgreSQL: up to 1024 chars (scram-sha-256)
- MySQL: ~255 recommended
- MongoDB: no explicit limit
- Redis: no limit

Computed semantics:

- A computed key can depend on raw keys whose `rotation.mode` is `external`/`manual`.
- This is the normal case for things like `DATABASE_URL` composed from `username`/`password`.
- The computed key itself is neither external nor manual; only its inputs are.

Operational hints (optional):

- `consumers[]` (deployments/jobs to restart/verify)
- `requiresRestart` (bool)

## Expirations and reminders

Goal: keep expiration awareness in Git without putting any secret values in Git.

- Expiration is per key (`keys[].expiry.expiresAt`) because different keys within one SealedSecret can have different lifetimes.
- waxseal surfaces expirations in CLI output (see CLI plan) and can optionally sync reminders into Google Calendar.
- Calendar integration does not store any calendar tokens/credentials in the repo; it uses Application Default Credentials.

## Metadata hygiene (avoid leaking info)

- Do not put credentials in any metadata fields.
- Prefer generic GSM secret IDs and labels over vendor-specific or username-containing names.
- For operator hints, prefer `keys[].operatorHints.gsm` rather than inline URLs/notes.
- For computed values, assume `computed.params` may leak internal hostnames.
  - Prefer `computed.paramsRef` for public repos.

Validation rules (suggested):

- If `keys[].operatorHints` is present:
  - validate URLs are `https://` (or explicitly allow `http://` via config)
  - warn if a URL contains `@`, `token=`, `key=`, `sig=`, or similar
  - enforce GSM payload size <= 64 KiB
- If `computed.params` is present:
  - warn if values look like internal hostnames (policy configurable)

## State (`.waxseal/state.yaml`)

Non-secret bookkeeping (optional):

- `lastCertFingerprintSha256`
- `rotations[]`:
  - `shortName`
  - `keyName`
  - `rotatedAt`
  - `mode` (`reseal` | `rotate`)
  - `gsm` (optional)
    - `secretResource`
    - `version`

Retirement audit (optional):

- `retirements[]`:
  - `shortName`
  - `retiredAt`
  - `reason`

## Why this shape

- Keeps the GitOps repo as the single place to see “what exists and how to rotate it”.
- Avoids guessing from ciphertext-only manifests.
- Enables stable targeting by `shortName` across file moves/renames.

## Notes on adoption and ambiguity

- When `discover` adopts a SealedSecret, waxseal cannot reliably infer whether a key is:
  - truly generated (versus a human-chosen secret)
  - externally-rotated (versus “set once and forget”)
  - computed (versus a pasted URL containing credentials)
- Default to `unknown` and require explicit classification over unsafe guessing.

## Key invariant for reseal

- Reseal must not change values.
- Therefore, metadata must record the GSM version used for each key.
- `rotate` is the operation that creates a new GSM version and updates metadata.
